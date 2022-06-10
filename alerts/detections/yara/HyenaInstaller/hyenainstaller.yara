rule HyenaInstaller {

meta:
  author = "Courtney Falk (cfalk)"
  last_updated = "2022-05-18"
  category = "Tools"
  confidence = "medium"
  description = "Detects installer binaries for the Hyena Active Directory utility"

strings:
  $company = "SystemTools Software Inc"
  $companyUrl = "www.systemtools.com"
  $originalFile = /Hyena_(English|Spanish|French|German)_x(86|64)\.exe/
  $installShield = "InstallShield"
  $installScript = "InstallScript"

condition:
  all of them
}