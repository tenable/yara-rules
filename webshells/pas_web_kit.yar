rule PAS_TOOL_PHP_WEB_KIT
{
    meta:
        description = "PAS TOOL PHP WEB KIT FOUND"
        source = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
        filetype = "PHP"

    strings:
        $php = "<?php"
        $base64decode = /\='base'\.\(\d+\*\d+\)\.'_de'\.'code'/ 
        $strreplace = "(str_replace("
        $md5 = ".substr(md5(strrev("
        $gzinflate = "gzinflate"
        $cookie = "_COOKIE"
        $isset = "isset"

    condition:
        (filesize > 20KB and filesize < 22KB) and
        #cookie == 2 and
        #isset == 3 and
        all of them
}

