# TlsCertificateVarification

.Description
  Used to check if On-Premises send/receive connectors are correctly configured for TLS communication. This script will examine both HCW and non-HCW created on-premises connectors with regards to the certificate configurations.
  Script performs following checks:
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
