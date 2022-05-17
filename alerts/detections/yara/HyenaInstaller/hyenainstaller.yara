rule HyenaInstaller {

meta:
  author = "Courtney Falk (cfalk)"
  last_updated = "2022"
  category = "Tools"
  confidence = "medium"
  description = "Detects installer binaries for the Hyena Active Directory utility"

strings:
  $company = "SystemTools Software Inc"
  $companyUrl = "www.systemtools.com"
  $originalFile = "Hyena_(English|Spanish|French|German)_(x86|x64).exe"
  $installShield = "InstallShield"
  $installScript = "InstallScript"

condition:
 ($company and $companyUrl and $originalFile and $installShield and $installScript)
}