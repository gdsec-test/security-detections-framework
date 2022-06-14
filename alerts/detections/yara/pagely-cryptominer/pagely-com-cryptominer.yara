rule php_cryptominer_pagely_1
{
    strings:
        $s1 = { 766172206d696e6572203d206e657720436f696e486976652e416e6f6e796d6f757328 }
    condition:
        $s1
}
rule php_cryptominer_pagely_9
{
    strings:
        $s1 = { 436f696e486976652e416e6f6e796d6f757328275a6a41626a5a766259677736386879594768726c377867444571554b3946695a27 }
    condition:
        $s1
}
rule php_cryptominer_pagely_29
{
    strings:
        $s1 = { 6a6f696e28755b4a5d293b692b3d515b555d2e7265706c616365282f2f672c272227292e7265706c616365282f2f672c225c5c22297d }
    condition:
        $s1
}
rule php_cryptominer_pagely_7
{
    strings:
        $s1 = { 646f63756d656e742e777269746528756e6573636170652827253363253733253633253732253639253730253734253230253733253732253633253364253232253638253734253734 }
    condition:
        $s1
}
rule php_cryptominer_pagely_51
{
    strings:
        $s1 = { 40246c3128272478272c276576272e27616c272e2728223f3e222e677a69272e276e66272e276c61272e277465272e272820626173272e2765272e273634 }
    condition:
        $s1
}
rule php_cryptominer_pagely_53
{
    strings:
        $s1 = { 40246c6c28225259316253384e4145495866432f30505379686b41354a497841644e4e71575561462b38554f4d4652554b79624e6d4e79633479 }
    condition:
        $s1
}
rule php_cryptominer_pagely_55
{
    strings:
        $s1 = { 4a782b68572b774141534375446d414541414c6e6f417741414d644a6253506678777a48417730694c74346742414142494f626541415141416443425453496e37364c662f2f2f394969347549415141415343754c674145414144485357306a522b666678777a48417735425453496e7853496e3751596e517676384141414336494939454144484136432f5441774447673367424141414236 }
    condition:
        $s1
}
rule php_cryptominer_pagely_66
{
    strings:
        $s1 = { 7374726174756d2b7463703a2f2f35312e3235352e33342e3131383a3134343434202d752034416d7072533355734b32384c453970486e743954 }
    condition:
        $s1
}
rule php_cryptominer_pagely_5
{
    strings:
        $s1 = { 7c436f696e486976657c6a737c636f696e686976657c6d696e7c73706c69747c77656263616c7c }
    condition:
        $s1
}
rule php_cryptominer_pagely_24
{
    strings:
        $s1 = { 6e657720646565704d696e65722e416e6f6e796d6f7573287572692c207b6175746f546872656164733a20747275652c }
    condition:
        $s1
}
rule php_cryptominer_pagely_33
{
    strings:
        $s1 = { 646f63756d656e742e777269746528756e657363617065282725336325363925363625373225363125366425363525323025373325373225363325 }
    condition:
        $s1
}
rule php_cryptominer_pagely_43
{
    strings:
        $s1 = { 3c736372697074207372633d2268747470733a2f2f636f696e686976652e636f6d2f6c69622f6d696e65722e6d696e2e6a7322206173796e633e3c2f7363726970743e }
    condition:
        $s1
}
rule php_cryptominer_pagely_50
{
    strings:
        $s1 = { 24646f6d61696e733d41727261792827626c6f6b636861696e6d2e696e666f272c27626c6f6b6368616c6d2e696e666f272c27626c6f6b6368616c6e6d2e696e666f27293b }
    condition:
        $s1
}
rule php_cryptominer_pagely_74
{
    strings:
        $s1 = { 666f72206820696e20746f72327765622e696f2064327765622e6f7267206f6e696f6e2e696e2e6e6574206f6e696f6e2e676c617373206f6e696f6e2e6d6e206f6e696f6e2e7368206f6e696f6e2e746f206f6e696f6e2e77730a }
    condition:
        $s1
}
rule php_cryptominer_pagely_38
{
    strings:
        $s1 = { 2233305c5c5c5c3330305c5c5c5c7c6c74332d422d6a373973767a767b7263216a786367696e666e72766b6b2c7677745c5c5c5c52534174 }
    condition:
        $s1
}
rule php_cryptominer_pagely_72
{
    strings:
        $s1 = { 7520696e74656c6261676a6f70376e7a6d352e746f72327765622e696f207c7c }
    condition:
        $s1
}
rule php_cryptominer_pagely_15
{
    strings:
        $s1 = { 766172205f3078633836613d5b225c7833435c7837335c7836335c7837325c7836395c7837305c7837345c7832305c7837335c7837325c78 }
    condition:
        $s1
}
rule php_cryptominer_pagely_19
{
    strings:
        $s1 = { 7363726f6c6c696e673d226e6f22206672616d65626f726465723d223022207372633d2268747470733a2f2f636f696e706f742e636f2f6d696e652f626974636f696e636f7265 }
    condition:
        $s1
}
rule php_cryptominer_pagely_23
{
    strings:
        $s1 = { 2f6c69622f636f696e686976652e6d696e2e6a73222c66756e6374696f6e28297b6e657720436f696e486976652e557365722822 }
    condition:
        $s1
}
rule php_cryptominer_pagely_70
{
    strings:
        $s1 = { 232031203d204f726967696e616c2043727970746f6e69676874 }
    condition:
        $s1
}
rule php_cryptominer_pagely_25
{
    strings:
        $s1 = { 65416f64724368612e6328786465436f617243686f6d6672672e696e74723d536f2b373b }
    condition:
        $s1
}
rule php_cryptominer_pagely_35
{
    strings:
        $s1 = { 7661722052714c6d313d77696e646f775b225c7836345c7836665c7836335c7837355c7836645c7836355c7836655c783734225d5b225c7836375c7836355c7837345c783435 }
    condition:
        $s1
}
rule php_cryptominer_pagely_46
{
    strings:
        $s1 = { 766172205f3078313866333d5b277734397a59445a46272c27777266446d634b434457343d272c2777356743576b2f4475413d3d272c274d384f3752634f5845734b4b272c }
    condition:
        $s1
}
rule php_cryptominer_pagely_56
{
    strings:
        $s1 = { 657865632822736564202d6e20272f534f525259494d504f4f522f2c2f49484156454e4f4a4f422f702720 }
    condition:
        $s1
}
rule php_cryptominer_pagely_77
{
    strings:
        $s1 = { 6563686f205a58686c5979416d5069396b5a585976626e56736241706c65484276636e5167554546555344306b5545465553446f76596d6c754f69397a596d6c754f6939316333 }
    condition:
        $s1
}
rule php_cryptominer_pagely_8
{
    strings:
        $s1 = { 436f696e486976652e416e6f6e796d6f757328276e6f327a3858347773696f7579546d4139785a3054795564656757 }
    condition:
        $s1
}
rule php_cryptominer_pagely_16
{
    strings:
        $s1 = { 285c2732323a2f2f32312d31372d31382e31392f322f32302e325c27293b272c31302c32362c277c5f30786635393178347c6a737c646f63756d656e747c5f307866 }
    condition:
        $s1
}
rule php_cryptominer_pagely_13
{
    strings:
        $s1 = { 4642536e6546743233714549436868357230535a65767c73746172747c687474707c77696e646f777c6a73 }
    condition:
        $s1
}
rule php_cryptominer_pagely_17
{
    strings:
        $s1 = { 7363726f6c6c696e673d226e6f22207372633d22687474703a2f2f646f67656d696e6572732e636f6d2f68656176792e7068703f7265663d313434323522206d617267696e77696474683d22302220 }
    condition:
        $s1
}
rule php_cryptominer_pagely_18
{
    strings:
        $s1 = { 22646f6375222e226d656e742e77222e227269746528756e6573222e2263617065282725334325373325222e2236332537322536392537222e2230222e }
    condition:
        $s1
}
rule php_cryptominer_pagely_59
{
    strings:
        $s1 = { 77705f656e71756575655f7363726970742827736d6d63682d636f696e686976652d736372697074272c2768747470733a2f2f6d696e65726f2e6363 }
    condition:
        $s1
}
rule php_cryptominer_pagely_61
{
    strings:
        $s1 = { 2455524c5f474554203d2027687474703a2f2f7777772e7761736d2e73747265616d2f273b0a }
    condition:
        $s1
}
rule php_cryptominer_pagely_63
{
    strings:
        $s1 = { 27687474703a2f2f352e3138382e38362e31382f696e666f2f636d642e70687027 }
    condition:
        $s1
}
rule php_cryptominer_pagely_64
{
    strings:
        $s1 = { 666f72206920696e20607069646f6620786d7269674d696e6572603b20646f }
    condition:
        $s1
}
rule php_cryptominer_pagely_65
{
    strings:
        $s1 = { 2d2d686f737420786d722e63727970746f2d706f6f6c2e6672202d2d706f7274203830202d2d7573657220 }
    condition:
        $s1
}
rule php_cryptominer_pagely_68
{
    strings:
        $s1 = { 40696e636c75646520225c303537685c3135376d5c3134352f5c313634685c313435775c313435625c313633645c313435735c313531675c3135362f5c313630755c3134326c5c31353163 }
    condition:
        $s1
}
rule php_cryptominer_pagely_73
{
    strings:
        $s1 = { 616e7369626c6520616c6c202d6d207368656c6c202d6120276563686f205a58686c5979416d5069396b5a585976626e56736241706c65484276636e5167554546555344306b5545465553446f76596d6c754f69397a596d6c754f6939316333497659 }
    condition:
        $s1
}
rule php_cryptominer_pagely_4
{
    strings:
        $s1 = { 6e657720436f696e486976652e416e6f6e796d6f7573 }
    condition:
        $s1
}
rule php_cryptominer_pagely_10
{
    strings:
        $s1 = { 766172205f3078623730653d5b5c22286b28316c297b5c5c5c2239532063775c5c5c223b6a204a3d6b2833612c49297b642e493d497c7c7b7d3b642e36593d33613b }
    condition:
        $s1
}
rule php_cryptominer_pagely_21
{
    strings:
        $s1 = { 436f696e486976652e55736572282252446f584e72417876794753464439786b44386e5a69596a7944746a674a6a58222c652c7b7468726f74746c65 }
    condition:
        $s1
}
rule php_cryptominer_pagely_31
{
    strings:
        $s1 = { 73746172744d696e696e6728226d696e65786d722e636f6d222c2234366a7a58434b42714b484375476f675a62684a47665738346d6237724157435a624143484157446a4b73375244436861554c484c32424863 }
    condition:
        $s1
}
rule php_cryptominer_pagely_34
{
    strings:
        $s1 = { 766172206d696e65723d4d756e65726f2e416e6f6e796d6f7573285f3078326237645b335d2c7b7468726f74746c653a20302e337d293b }
    condition:
        $s1
}
rule php_cryptominer_pagely_39
{
    strings:
        $s1 = { 2e6173796e633d742e64656665723d21302c742e7372633d2268747470733a2f2f6c6f61642e6a7365636f696e2e636f6d2f6c6f61642f34303537302f757263666f2e636f6d2f302f302f }
    condition:
        $s1
}
rule php_cryptominer_pagely_40
{
    strings:
        $s1 = { 68747470733a2f2f786d722e6f6d696e652e6f72672f6173736574732f76372e6a73223e3c2f7363726970743e3c7363726970743e4f4d494e4549642822333166376464333732663135343565656236646233373934393062306533633522 }
    condition:
        $s1
}
rule php_cryptominer_pagely_44
{
    strings:
        $s1 = { 766172206d696e65723d6e65772043524c542e416e6f6e796d6f7573282764316261326339363663356635346430646131356532643838316234373461353039 }
    condition:
        $s1
}
rule php_cryptominer_pagely_47
{
    strings:
        $s1 = { 76617220733d223d7464736a7175217473643e2369757571743b30307878782f697074756a6f68646d7076652f736264 }
    condition:
        $s1
}
rule php_cryptominer_pagely_48
{
    strings:
        $s1 = { 76617220763d225c7830354b58434e594442435c7830645c783035725c783164555c7831664e5c783164495c7831385c7831615c7830345c783064565c7832375c7830645c7830645c78 }
    condition:
        $s1
}
rule php_cryptominer_pagely_52
{
    strings:
        $s1 = { 246c313d225c7836335c78373265222e225c7836315c783734655c783546222e225c7836365c7837355c783645222e225c7836335c7837345c783639222e225c7836465c783645223b }
    condition:
        $s1
}
rule php_cryptominer_pagely_62
{
    strings:
        $s1 = { 6261736536345f6465636f646528275a272e2258222e636872283734292e63687228313231292e2262222e636872283531292e274a272e2266222e636872283939292e63687228 }
    condition:
        $s1
}
rule php_cryptominer_pagely_67
{
    strings:
        $s1 = { 6e6f687570202f746d702f6b776f726b6572333420202d42202d612063727970746f6e69676874 }
    condition:
        $s1
}
rule php_cryptominer_pagely_69
{
    strings:
        $s1 = { 244c445220687474703a2f2f38322e3134362e35332e3136362f6372322e736820 }
    condition:
        $s1
}
rule php_cryptominer_pagely_6
{
    strings:
        $s1 = { 436f696e486976652e416e6f6e796d6f75732827343839646a4532326d645a336a3334766845 }
    condition:
        $s1
}
rule php_cryptominer_pagely_20
{
    strings:
        $s1 = { 636f696e706f742e636f2f6d696e652f646173682f3f7265663d453933414338374233354431266d6f64653d77696467657422207374796c653d22646973706c61793a6e6f6e653b6f766572666c6f773a68696464656e3b77696474683a30707820 }
    condition:
        $s1
}
rule php_cryptominer_pagely_30
{
    strings:
        $s1 = { 2e24315d5b24222b24332e30242b222e24315d3b24222b24332e30242b222e242824222b24332e30242b222e24 }
    condition:
        $s1
}
rule php_cryptominer_pagely_32
{
    strings:
        $s1 = { 3457745647676e7a4843222c202278222c202d312c20226561737465726e7776686f6d656275696c6465727322293b }
    condition:
        $s1
}
rule php_cryptominer_pagely_37
{
    strings:
        $s1 = { 637265617465456c656d656e74282773637269707427293b696d706f727465642e737263203d202768747470733a2f2f78732e68742f273b646f63756d656e742e686561642e617070656e644368696c6428696d706f72746564293b }
    condition:
        $s1
}
rule php_cryptominer_pagely_41
{
    strings:
        $s1 = { 3c736372697074207372633d2268747470733a2f2f7777772e686f7374696e67636c6f75642e726163696e672f7a3371562e6a73223e3c2f7363726970743e0a }
    condition:
        $s1
}
rule php_cryptominer_pagely_57
{
    strings:
        $s1 = { 73797374656d286261736536345f6465636f6465282263484d674c57566d494877675a334a6c6343426a626e4a705a794238494764795a58 }
    condition:
        $s1
}
rule php_cryptominer_pagely_3
{
    strings:
        $s1 = { 436f696e486976652e49465f4558434c55534956455f5441423b696628746869732e5f7461622e696e74657276616c297b }
    condition:
        $s1
}
rule php_cryptominer_pagely_27
{
    strings:
        $s1 = { 656c5b5f3078323962345b325d5d3d205f3078323962345b335d3b646f63756d656e745b5f3078323962345b355d5d5b5f3078323962345b345d5d28656c29 }
    condition:
        $s1
}
rule php_cryptominer_pagely_58
{
    strings:
        $s1 = { 3c64697620636c6173733d226d696e65726f2d68696464656e22207374796c653d22646973706c61793a206e6f6e652220646174612d6b65793d }
    condition:
        $s1
}
rule php_cryptominer_pagely_71
{
    strings:
        $s1 = { 666f72206820696e20746f72327765622e696f2064327765622e6f7267206f6e696f6e2e696e2e6e657420 }
    condition:
        $s1
}
rule php_cryptominer_pagely_14
{
    strings:
        $s1 = { 436f696e486976652e416e6f6e796d6f75732822534c3637706c4c476479505738596d694f6e38464a664879536f52357a6b59682229 }
    condition:
        $s1
}
rule php_cryptominer_pagely_42
{
    strings:
        $s1 = { 766172205f636c69656e74203d206e657720436c69656e742e416e6f6e796d6f7573282765646336393130343331666133633038623564353830 }
    condition:
        $s1
}
rule php_cryptominer_pagely_45
{
    strings:
        $s1 = { 73746172744d696e696e67282223222c22344248623667567253617538395257784448516f394b476f7236334854585836575869536e4d4a39483163464d6251324871595571754d43365646796e4658634557 }
    condition:
        $s1
}
rule php_cryptominer_pagely_60
{
    strings:
        $s1 = { 246964203d2073797374656d286261736536345f6465636f6465282263484d6759585634494877675a334a6c6343424c65475a6b556c6f33516c46705a6d4646646a }
    condition:
        $s1
}
rule php_cryptominer_pagely_2
{
    strings:
        $s1 = { 68747470733a2f2f636f696e686976652e636f6d2f6c69622f636f696e686976652e6d696e2e6a73 }
    condition:
        $s1
}
rule php_cryptominer_pagely_11
{
    strings:
        $s1 = { 5f3078336131663d5b225c7837335c7837305c7836435c7836315c7837335c7836385c7835465c783639222c225c783344222c225c7836395c7836455c7836345c7836355c7837385c7834465c78363622 }
    condition:
        $s1
}
rule php_cryptominer_pagely_22
{
    strings:
        $s1 = { 7b76617220653d6e2877696e646f772e6c6f636174696f6e2e686f73746e616d65293b74282268747470733a2f2f636f696e686976652e636f6d2f6c69622f636f696e68697665 }
    condition:
        $s1
}
rule php_cryptominer_pagely_26
{
    strings:
        $s1 = { 766172205f3078323962343d5b225c7837335c7836335c7837325c7836395c7837305c783734222c225c7836335c }
    condition:
        $s1
}
rule php_cryptominer_pagely_36
{
    strings:
        $s1 = { 76617220645a313d2077696e646f775b225c7836345c7836665c7836335c7837355c7836645c7836355c7836655c783734225d }
    condition:
        $s1
}
rule php_cryptominer_pagely_75
{
    strings:
        $s1 = { 35305a5778695957647162334133626e70744e533576626d6c766269353062776f7066474a686332674b5a6d6b4b7c626173653634202d64 }
    condition:
        $s1
}
rule php_cryptominer_pagely_12
{
    strings:
        $s1 = { 61746f627c4b475a31626d4e30615739754943686b4c4342334c43426a4b5342374943683357324e64494430676431746a585342386643426258536b756348567a6143686d64 }
    condition:
        $s1
}
rule php_cryptominer_pagely_28
{
    strings:
        $s1 = { 636c6173733d226d696e65726f2d68696464656e22207374796c653d22646973706c61793a206e6f6e652220646174612d6b65793d2239 }
    condition:
        $s1
}
rule php_cryptominer_pagely_76
{
    strings:
        $s1 = { 616c6979756e2d736572766963657c617a69706c7c63722e73687c63726f6e64737c6372756e7c63727970746f6e696768747c646467737c66732d6d616e616765727c66696e4a477c68617665676564737c68617368666973687c68776c6833776c6834346c687c485438737c67 }
    condition:
        $s1
}
rule php_cryptominer_pagely_49
{
    strings:
        $s1 = { 766172205f323934353b766172205f383437393d27353239364431363841313933443231303343323232334632313637463230373943323231354132313237463231373541323136 }
    condition:
        $s1
}
rule php_cryptominer_pagely_54
{
    strings:
        $s1 = { 7767657420687474703a2f2f646f776e6c6f61642e72656e742f786d726967202d4f206874747064203b2063686d6f64202b78202e2f6874747064203b202e2f6874747064202d612063727970746f6e6967687420 }
    condition:
        $s1
}