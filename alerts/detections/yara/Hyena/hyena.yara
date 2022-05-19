rule Hyena {

meta:
  author = "Courtney Falk (cfalk)"
  last_updated = "2022-05-18"
  category = "Tools"
  confidence = "medium"
  description = "Detects installer binaries for the Hyena Active Directory utility"

strings:
  $company = "SystemTools Software Inc"
  $companyUrl = "www.systemtools.com"
  $withVersion = /Hyena v\d+?\.\d+?.\d+?.\d+?/
  $symbolsPath = /\\x(86|64)\\Hyena (English|Spanish|French|German) Release\\hyena_x(86|64)\.pdb/
  $import1 = "WNetGetConnection"
  $import2 = "ShellExecute"

condition:
  all of them
}