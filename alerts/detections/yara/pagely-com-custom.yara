rule php_phpinfo_custom_0 {
    strings:
       $s1 = "phpinfo();"
    condition:
       $s1 and filesize < 70
}

rule php_phpunit_custom_0 {
    strings:
       $s1 = "eval('?>' . file_get_contents('php://input'));"
    condition:
       $s1 and filesize < 70
}

rule php_alphabet_inject_custom_0 {
    strings:
       $re = /\$array_name = \$alphabet\[[0-9]{1,2}\]\.\$alphabet\[[0-9]{1,2}\]/
    condition:
       $re
}

rule php_argexec_custom_0 {
    strings:
       $s1 = "cmd=$_GET['cmd'];"
       $s2 = "system($cmd);"
       $s3 = "exec($cmd);"
    condition:
       ($s1 or $s2) and ($s1 or $s3)
}

rule php_argexec_custom_1 {
   strings:
      $s0 = "$_REQUEST["
      $s1 = "exec(\"/bin/bash"
   condition:
      all of them
}

rule php_wpcoremodule_custom_0 {
    strings:
       $s1 = "unlink('wp-core-module.php');"
    condition:
       $s1
}

rule php_chr_multiple_0 {
   strings:
      $re= /<\?php([\s]*\$[\w][\s]*=| echo)[\s]*chr\([^;]+chr\([\d]+\)[\s]*\.[\s]*chr\(/
   condition:
      $re
}

rule php_optproxy_custom_0 {
    strings:
       $s1 = "$preffmhomeurl=$table_prefix"
       $s2 = "readValueFromBDLM"
       $s3 = "$tasksettings[\"cloacking\"]"
    condition:
       all of them
}

rule php_interconnectit_custom_0 {
    strings:
       $s1 = "interconnectit.com"
    condition:
       $s1 at 1909
}

rule php_scandir_custom_0 {
    strings:
       $s1 = "str_ireplace(\"Set the error_reporting\""
       $s2 = "in_array(\"configuration.php\",scandir($p)"
       $s3 = "in_array(\"components\",scandir($p)"
    condition:
       all of them
}

rule php_striplple_custom_0 {
    strings:
       $s1 = "striplple"
    condition:
       $s1
}

rule php_striplple_custom_1 {
    strings:
       $s1 = "if(isset($_POST["
       $s2 = "&& md5($_POST["
       $s3 = "base64_decode($_POST"
       $s4 = "file_put_contents"
       $s5 = "if(file_exists("
       $s6 = "{include("
       $s7 = ";unlink("
    condition:
       all of them
}

rule php_eval_cookie_custom_0 {
    strings:
       $re = /\$[\w]+[\s]*=[\s]*\$_COOKIE;[\s]*\(count\(\$[\w]+\)==[\d]+&&in_array\(gettype[^:\n]+:\$[\w]+;/
    condition:
       $re
}

rule php_jumpurl_custom_0 {
    strings:
       $s1 = "$jump_url"
       $s2 = "$crawler_url=$_REQUEST"
       $s3 = "function fetch_by_curl("
    condition:
       all of them
}

rule php_classic_custom_0 {
    strings:
       $s1 = "function classic()"
       $s2 = "$_COOKIE"
       $s3 = "return 0;"
    condition:
       all of them
}

rule php_fakeautoptimize_custom_0 {
    strings:
       $s1 = "base64_decode(self::$s["
       $s2 = "@header("
       $s3 = "function get_js("
       $s4 = "if (isset($_SERVER["
       $s5 = "= urlencode(base64_encode(json_encode("
    condition:
       all of them
}

rule php_generic_crontab_injector_1 {
   strings:
      $s0 = "echo \"* * * * * wget"
      $s1 = "&& crontab"
      $s2 = "echo \"exec"
   condition:
      all of them
}

rule php_fpc_tmp_1 {
   strings:
      $s0 = "@unlink(__FILE__);"
      $s1 = "ZmlsZV9wdXRfY29udGVudHMoc3lzX2dldF90ZW1wX2Rp"
      $s2 = "bGVfcHV0X2NvbnRlbnRzKHN5c19nZXRfdGVtcF9k"
      $s3 = "aWxlX3B1dF9jb250ZW50cyhzeXNfZ2V0X3RlbXBfZGly"
   condition:
      ($s0 and $s1) or ($s0 and $s2) or ($s0 and $s3)
}

rule php_array_obfuscation_1 {
   strings:
      $re = /\$\w+\s*=\s*[\'"][^=]+;\s*(\$\w+\s*=\s*array\(\)\s*;\s*)?\$\w+(\[\])?\s*=\s*\$\w+\[\d+\]\s*\.\s*\$\w+\[\d+\]\s*\.[^;]+;/
   condition:
      $re
}

rule php_wsal_ext_libs_custom_0 {
   strings:
      $s0 = "$_SERVER[base64_decode("
      $s1 = "CURLOPT_RETURNTRANSFER,1)"
   condition:
      all of them
}

rule php_wsal_ext_libs_custom_1 {
   strings:
      $s0 = "if(isset($_COOKIE['"
      $s1 = "die('"
      $s2 = "<script language=\"javascript\""
   condition:
      all of them
}

rule js_injection_custom_0 {
    strings:
      $re = /;[\s]*if[\s]*\(nds.[\s]*===[\s]*undefined\)[\s]*\{[\s]*[^\n]+HttpClient[\s]*=[\s]*function/
    condition:
      $re
}

rule js_injection_custom_1 {
    strings:
      $s0 = "base64_decode(self"
      $s1 = "isset($_SERVER["
      $s2 = "curl_setopt("
      $s3 = "urlencode(base64_encode(json_encode("
    condition:
       all of them
}

rule js_injection_custom_2 {
   strings:
      $s0 = "register_shutdown_function"
      $s1 = "is_user_logged_in"
      $s2 = "setcookie("
      $s3 = "PHNjcmlw"
      $s4 = "Y3JpcHQK"
      $s5 = "c2NyaXB0"
   condition:
      ($s0 and $s1 and $s2 and $s3) or ($s0 and $s1 and $s2 and $s4) or ($s0 and $s1 and $s2 and $s5)
}

rule php_backdoor_custom_567 {
    strings:
      $s0 = "@ini_set('display_errors','Off');"
      $s1 = "$password"
      $s2 = "str_rot13"
    condition:
      all of them
}

rule php_backdoor_xor_1 {
   strings:
      $re = /function\s*\w+\s*\(\$\w+\s*,\s*\$\w+\)[^\^]+\^\s*\$\w+[^\^]+\^\s*\$\w+\[\$\w+\s*\%\s*\$\w+\]/
   condition:
      $re
}

rule php_fakewplazyload_custom_0 {
    strings:
       $s1 = "gzuncompress(strrev(substr($"
    condition:
       $s1
}

rule php_hide_wpusers_1 {
   strings:
      $s0 = "add_filter(\"views_users\", \"dt_list_table_views\");"
   condition:
      $s0
}