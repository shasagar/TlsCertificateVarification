<#
MIT License

Copyright (c) 2024 Shashank Agarwal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

<#
 .Synopsis
  Script to validate Inbound/Outbound StartTLS configuration
 .Description
  Used to check if On-Premises send/receive connectors are correctly configured for TLS communication. This script will examine both HCW and non HCW created on-premises connectors with regards to the certificate configurations.
  Scritp performs following checks:
  -Default Frontend Receive Connector should have TLS as a Auth Machanisum
  -Send/Receive connectors have TlsCertificateName or FQDN set.
  -Server has correct 3rd party certificate that matches with send/receive connectors' configuration.
  -Script validates matching 3rd party certificate chain as well.
 .Required Inputs
  -Make sure you are running the script on the correct ServerRole [Edge/Hub]
 .Example
   # Check TLS certificate configuration
   .\TlsCertificateCheck.ps1
#>

# Version 1.0.0
# Exchange versions supported: 2016, 2019

$time = Get-Date -Format MMddyyyyhhmmss
$folderName = "LogFiles" + $time
New-Item -itemtype Directory -Path .\$folderName

$script:logFile = ".\$folderName\TlsCertVarification.log"

#This function is to record script progress
Function WriteLog 
{
Param ([string]$string, $color, [Switch]$nonInteractive)

# Get the current date
[string]$date = Get-Date -Format G
# Write everything to the log file
( "[" + $date + "] - " + $string) | Out-File -FilePath $script:logFile -Append
# If NonInteractive true then supress host output
	if (!($nonInteractive))
	{
		( "[" + $date + "] - " + $string) | Write-Host -f $color
	}
}

#This function is to collect the list of all 3rd party certificates on the server
Function ServerCertificateInventory 
{
Param ([string]$server)
$script:certtable = @()
writeLog -color cyan "Collecting 3rd party certificate info for server $server"

try
{
$certs = Get-ExchangeCertificate -server $server -ErrorAction Stop | where-object {$_.IsSelfSigned -ne $TRUE}
	if(!($certs))
	{
	writelog -color Red "No 3rd party certificate was found on the server $server"
	Continue
	}
}
catch
{
WriteLog -color Red $_.Exception.Message
Continue
}
	foreach ($cert in $certs)
	{
		$certInfoTable = [PSCustomObject]@{
		Subject = $cert.subject
		thumbprint = $cert.thumbprint
		status = $cert.status
		validity = $cert.notafter
		tls = "<I>$($Cert.Issuer)<S>$($Cert.Subject)"
		domains = $cert.certificatedomains
		Services = $cert.Services
		}

		$script:certtable += $certInfoTable
	}
}

#This function is to create a table after validating certificates
Function CertficateSearchResults
{
	if($sendTable[$k].identity)
	{
	$sendid = $sendTable[$k].identity
	}
	Elseif($script:rcptTable[$i].identity)
	{
	$rcptid = $script:rcptTable[$i].identity
	}	
	$matchCertTable = [PSCustomObject]@{
	ServerName = $server
	SendConnector = $sendid
	ReceiveConnector = $rcptid
	CertificateThumbprint = $script:matchedCertThumbprint
	Status = $script:Info
	}
$script:finalTable += $matchCertTable
}

#This function is to verify certificate configuration on the send/receive connectors
Function CertificateValidation
{
Param ([string]$tlsCertName, [string]$fqdn)
$certCount = $script:certTable.count
[Boolean]$certCheckpoint = $False
	for($j=0; $j -lt $certCount; $j++)
	{
	writelog -color cyan "Checking certificate:" 
	writelog -color white $script:certTable[$j].thumbprint
		if ($tlsCertName)
		{
		writelog -color white "TlsCertificateName value found on the Connector, checking further..."
			if ($tlsCertName -eq $script:certTable[$j].tls)
			{
			$certCheckpoint = $true
			writelog -color green "Certificate matched"
			$script:matchedCertThumbprint = $certTable[$j].thumbprint
				[string]$certLocation = "Cert:\LocalMachine\My\" + "$script:matchedCertThumbprint"				
				Invoke-command -computername $server -ScriptBlock{
						try
						{
						$using:certLocation
						Get-ChildItem -Path $using:certLocation | Test-Certificate -ErrorAction Stop
						}
						catch
						{
						write-host -f red $_.Exception.message
						}
					
					}
			
				if($certTable[$j].validity -gt (get-date) -and $certTable[$j].status -eq "valid")
				{
					if($certTable[$j].services -match "SMTP")
					{
					$script:Info = "Certificate is valid and SMTP service is Enabled"
					}
					Else
					{
					$script:Info = "Certificate is valid but SMTP service is NOT enabled"
					}
				}
				Elseif($certTable[$j].status -ne "valid")
				{
				$script:Info = "Matched certificate status is not valid"
				}
			break
			}
		
			Else
			{
			$script:Info = "No matching cert was found"
			writelog -color yellow "No matching certificate was found"
			}
		
		}
		if([string]::IsNullOrEmpty($tlscertname) -and (-not([string]::IsNullOrEmpty($fqdn))))
		{
		writelog -color white "TlsCertificateName value not set on the Connector, searching certificate using FQDN set on the connector"
		writelog -color white $fqdn
			if ($certTable[$j].Subject.Substring(0,5) -eq "CN=*.")
			{
				if($fqdn.contains($certTable[$j].subject.Substring(5)))
				{
				$certCheckpoint = $true
				writelog -color green "Certificate matched"
				$script:matchedCertThumbprint = $certTable[$j].thumbprint
				[string]$certLocation = "Cert:\LocalMachine\My\" + "$script:matchedCertThumbprint"				
				Invoke-command -computername $server -ScriptBlock{
						try
						{
						$using:certLocation
						Get-ChildItem -Path $using:certLocation | Test-Certificate -ErrorAction Stop
						}
						catch
						{
						write-host -f red $_.Exception.message
						}
					
					}
					if($certTable[$j].validity -gt (get-date) -and $certTable[$j].status -eq "valid")
					{
						if($certTable[$j].services -match "SMTP")
						{
						$script:Info = "Certificate is valid and SMTP service is Enabled"
						}
						Else
						{
						$script:Info = "Certificate is valid but SMTP service is NOT enabled"
						}
					}
					Elseif($certTable[$j].status -ne "valid")
					{
					$script:Info = "Matched certificate status is not valid"
					}
				}
			break
			}
			Elseif ($certTable[$j].Domains.address -contains $fqdn)
			{
			$certCheckpoint = $true
			writelog -color green "matched"
			$script:matchedCertThumbprint = $certTable[$j].thumbprint
				try
				{
				Invoke-Command -ComputerName $server -ScriptBlock {(Get-ChildItem Cert:\LocalMachine\My | where {$_.thumbprint -eq $script:matchedCertThumbprint})| test-certificate}
				}
				Catch
				{
				Writelog -color Red $_.Exception.Message
				}
			
				if($certTable[$j].validity -gt (get-date) -and $certTable[$j].status -eq "valid")
				{
					if($certTable[$j].services -match "SMTP")
					{
					$script:Info = "Certificate is valid and SMTP service is Enabled"
					}
					Else
					{
					$script:Info = "Certificate is valid but SMTP service is NOT enabled"
					}
				}
				Elseif($certTable[$j].status -ne "valid")
				{
				$script:Info = "Matched certificate status is not valid"
				}
			break
			}
			Else
			{
			$script:Info = "No matching cert was found"
			writelog -color yellow "No matching certificate was found"
			#continue
			}
		}

		if(([string]::IsNullOrEmpty($tlscertname)) -and ([string]::IsNullOrEmpty($fqdn)))
		{
		writelog -color cyan "TlsCertificateName or FQDN is not set on the Connector, searching certificate using Server FQDN:" 
		writelog -color white $script:serverfqdn
			if ($certTable[$j].Subject.Substring(0,5) -eq "CN=*.")
			{
				if($script:serverfqdn.contains($certTable[$j].subject.Substring(5)))
				{
				$certCheckpoint = $true
				writelog -color green "Certificate matched"
				$script:matchedCertThumbprint = $certTable[$j].thumbprint
				[string]$certLocation = "Cert:\LocalMachine\My\" + "$script:matchedCertThumbprint"				
				Invoke-command -computername $server -ScriptBlock{
						try
						{
						$using:certLocation
						Get-ChildItem -Path $using:certLocation | Test-Certificate -ErrorAction Stop
						}
						catch
						{
						write-host -f red $_.Exception.message
						}
					
					}
					if($certTable[$j].validity -gt (get-date) -and $certTable[$j].status -eq "valid")
					{
						if($certTable[$j].services -match "SMTP")
						{
						$script:Info = "Certificate is valid and SMTP service is Enabled"
						}
						Else
						{
						$script:Info = "Certificate is valid but SMTP service is NOT enabled"
						}
					}
					Elseif($certTable[$j].status -ne "valid")
					{
					$script:Info = "Matched certificate status is not valid"
					}
				break
				}
				Else
				{
				$script:Info = "No matching cert was found"
				writelog -color yellow "No matching cert was found"
				}
			
			}
			elseif ($certTable[$j].Domains.address -contains $script:serverfqdn)
			{
			$certCheckpoint = $true
			writelog -color green "matched"
			$script:matchedCertThumbprint = $certTable[$j].thumbprint
				if($certTable[$j].validity -gt (get-date) -and $certTable[$j].status -eq "valid")
				{
					if($certTable[$j].services -match "SMTP")
					{
					$script:Info = "Certificate is valid and SMTP service is Enabled"
					}
					Else
					{
					$script:Info = "Certificate is valid but SMTP service is NOT enabled"
					}
				}
				Elseif($certTable[$j].status -ne "valid")
				{
				$script:Info = "Matched certificate status is not valid"
				}
			break
			}
			Else
			{
			$script:Info = "No matching cert was found"
			writelog -color yellow "No matching cert was found"		
			}		
		}
	}
	CertficateSearchResults
}

#Exchange Environment configuration logs
Get-ExchangeServer | Export-Clixml .\$folderName\ExchangeServerInfo.xml
Get-ReceiveConnector | Export-Clixml .\$folderName\ReceiveConnectorsInfo.xml
Get-SendConnector | Export-Clixml .\$folderName\SendConnectorsInfo.xml

$script:finalTable = @()
if (Get-ExchangeServer | Where-Object {$_.ServerRole -eq "Edge"})
{
    $serverStatusCheck = Read-host "Edge Server(s) exists in the environment. If you are using Edge Servers to send/receive emails to/from Exchange Online, make sure to run the script on the Edge Server to validate TLS Certificate configuration. Do you want to continue [Yes / No]"
}
if ($serverStatusCheck -eq "No")
{
    Writelog -color cyan "Script has been terminated by the admininstrator"
}
Else
{
    $mbxRoleSelection = Read-host "Are you running script on Edge or Hub? [type Edge or Hub]"
    if ($mbxRoleSelection -eq "Hub")
    {
        $Servers = Get-ExchangeServer | where-object {$_.ServerRole -ne "Edge"}
    }
    else 
    {
        $Servers = Get-ExchangeServer | where-object {$_.ServerRole -eq "Edge"}
    }
}
$sendTable = @()
$sendCons = Get-SendConnector | where-object {$_.AddressSpaces.Address -like "*onmicrosoft.com*" -and $_.Enabled -eq $true}
if(!($sendCons))
{
$sendCons = Get-SendConnector | where-object {$_.AddressSpaces.Address -eq '*'-and $_.Enabled -eq $True} 
}
#Collecting send connectors' information
foreach ($sendCon in $sendCons)
{
	$sendConTable = [PSCustomObject]@{
	Identity = $sendCon.Identity
	TlsCertName = $sendCon.TlsCertificateName
	FQDN = $sendCon.FQDN
	SourceTransportServers = $sendCon.SourceTransportServers.Name
	}
$sendTable += $sendConTable
}

#Validating certificate configuration on all the exchange servers 
foreach ($server in $servers)
{
$script:serverfqdn = $server.fqdn
WriteLog -color cyan -string "working on Server:"
writeLog -color white -string $script:serverfqdn
#Collect the information of all certificates:
$certFileName = $server.name + "certificateinfo.xml"
Get-ExchangeCertificate -Server $server.fqdn -ErrorAction SilentlyContinue | Export-Clixml .\$folderName\$certFileName

ServerCertificateInventory -Server $server
$sendCount = $sendTable.count
	For($k=0;$k -lt $sendCount; $k++)
	{
	$script:matchedCertThumbprint = $NULL
	$script:info = $NULL
		if($sendTable[$k].SourceTransportServers -contains $server.name)
		{
	
		WriteLog -color cyan -string "Checking SendConnector:"
		writelog -color white $sendTable[$k].Identity
		CertificateValidation -Server $server.name -tlsCertName $sendTable[$k].tlsCertName -fqdn $sendTable[$k].fqdn.domain
		}
	}
$script:rcptTable = @()
$rcptCons = get-receiveconnector -server $server | where-object {($_.TlsCertificateName -ne $NULL -or $_.identity -like '*Default Frontend*') -and $_.Enabled -eq $true}

#Collecting receive connectors information
	foreach ($rcptcon in $rcptcons)
	{
		$auth = $rcptcon.AuthMechanism.ToString()
		$auth = $auth.Split(',').Trim()
		if(!($auth.contains('Tls')))
		{
		writelog -color yellow "TLS Auth is not enabled on the receive connector:"
		writelog -color white $rcptcon
		continue
		}
		$rcptConTable = [PSCustomObject]@{
		Identity = $rcptCon.Identity
		TlsCertName = $rcptCon.TlsCertificateName
		FQDN = $rcptCon.FQDN
		}
		$script:rcptTable += $rcptConTable
	}
$rcptCount = $script:rcptTable.count
	for ($i = 0;$i -lt $rcptCount; $i++)
	{
	$script:matchedCertThumbprint = $NULL
	$script:info = $NULL
	Writelog -color cyan "Checking Receive Connector:"
	writelog -color white $script:rcptTable[$i].identity
	CertificateValidation -Server $server.name -tlsCertName $script:rcptTable[$i].tlsCertName -fqdn $script:rcptTable[$i].fqdn.domain
	}
}
 
#Appending all the collected information in a table 
$script:finalTable | Format-Table -Autosize
$script:finalTable | Format-Table -Autosize | Out-File -FilePath $script:logFile -Append
