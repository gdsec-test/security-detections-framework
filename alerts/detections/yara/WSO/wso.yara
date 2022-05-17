rule HyenaInstaller {

meta:
  author = "Courtney Falk (cfalk)"
  last_updated = "2022"
  category = "Tools"
  confidence = "high"
  description = "Detects the WSO PHP web shell"

strings:
  $loader = "UeXploiT"
  $body = "An0n_3xPloiTeR"

condition:
 ($loader and $body)
}