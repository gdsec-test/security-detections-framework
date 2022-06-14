rule php_backdoor_custom_91
{
    strings:
        $s1 = { 687474703a2f2f6f70656e70726f74656374312e6e65742f4c6f672f53746174462f537461742e7068703f69703d }
    condition:
        $s1
}
rule php_backdoor_custom_482
{
    strings:
        $s1 = { 2477696e203d20545255453b656c7365202477696e203d2046414c53453b696628697373657428245f4745545b??79??5d29297b6966284069735f646972 }
    condition:
        $s1
}
rule php_backdoor_custom_64
{
    strings:
        $s1 = { 696620284066696c655f6765745f636f6e74656e7473285c27272e55524c2e273f703d272e2470617373776f72642e272675726c3d5c27202e20245f5345525645525b5c27485454505f484f53545c275d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_71
{
    strings:
        $s1 = { 5d2840245f434f4f4b49455b }
    condition:
        $s1
}
rule php_backdoor_custom_279
{
    strings:
        $s1 = { 247265706c61636564203d207374725f7265706c61636528246e6565646c652c20246e6565646c652e2467656e636f64652c202467656e6572616c5f74656d706c617465293b }
    condition:
        $s1
}
rule php_backdoor_custom_379
{
    strings:
        $s1 = { 72656e616d65282777702d726d63632e7068702e737573706563746564272c2777702d726d63632e70687027293b }
    condition:
        $s1
}
rule php_backdoor_custom_381
{
    strings:
        $s1 = { 6966202866696c655f6578697374732865786563285c27756e7a6970206b726f626c2e7a69705c27293b }
    condition:
        $s1
}
rule php_backdoor_custom_418
{
    strings:
        $s1 = { 696628697373657428245f4745545b2773275d29297b6563686f20276e7364272e27666a6b273b }
    condition:
        $s1
}
rule php_backdoor_custom_419
{
    strings:
        $s1 = { 4c6a316a6148496f4a485a654a4773704f3256325957776f4a486f704f773d3d }
    condition:
        $s1
}
rule php_backdoor_custom_440
{
    strings:
        $s1 = { 6d6435282475707329203d3d20247570735f6d64352026262021656d7074792824485454505f504f53545f46494c45535b??75706c6f616466696c65??5d }
    condition:
        $s1
}
rule php_backdoor_custom_143
{
    strings:
        $s1 = { 474c4f42414c2024616c72656164797878783b }
    condition:
        $s1
}
rule php_backdoor_custom_168
{
    strings:
        $s1 = { 696628697373657428245f504f53545b22706870225d29297b406576616c287374726970736c617368657328245f504f53545b22706870225d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_105
{
    strings:
        $s1 = { 277072272e276567272e275f72272e2765706c61272e276365273b }
    condition:
        $s1
}
rule php_backdoor_custom_187
{
    strings:
        $s1 = { 3c3f706870206576616c2840245f524551554553545b2271713535653131225d293b }
    condition:
        $s1
}
rule php_backdoor_custom_276
{
    strings:
        $s1 = { 6563686f20223c6b756b753e222e246469722e223c2f6b756b753e223b }
    condition:
        $s1
}
rule php_backdoor_custom_530
{
    strings:
        $s1 = { 2a2f2069662028697373657428245f524551554553545b276b6964736964275d29297b2475736572203d206765745f757365725f62792820276964272c20245f524551554553545b276b6964736964275d20293b }
    condition:
        $s1
}
rule php_backdoor_custom_81
{
    strings:
        $s1 = { 6372656174655f66756e6374696f6e2822222c206261736536345f6465636f6465 }
    condition:
        $s1
}
rule php_backdoor_custom_192
{
    strings:
        $s1 = { 613d636872283938292e636872283937292e63687228313135292e63687228313031292e636872283534292e636872283532292e636872283935292e6368722831303029 }
    condition:
        $s1
}
rule php_backdoor_custom_90
{
    strings:
        $s1 = { 687474703a2f2f626f7473767362726f77736572732e62697a2f5374617469737469632f537461742e7068703f69703d }
    condition:
        $s1
}
rule php_backdoor_custom_555
{
    strings:
        $s1 = { 245F5F5F5F5F5F5F5F3B }
    condition:
        $s1
}
rule php_backdoor_custom_450
{
    strings:
        $s1 = { 247365727665725f75726c203d2027687474703a2f2f64726f7073666f72756d732e72752f70616e656c2f70726f632f726563656976655f726573756c742e706870273b }
    condition:
        $s1
}
rule php_backdoor_custom_511
{
    strings:
        $s1 = { 5465726d696e616c20706870207c204e67696e784861586f72 }
    condition:
        $s1
}
rule php_backdoor_custom_543
{
    strings:
        $s1 = { 696628697373657428245f504f53545b2770617373275d2929207b696628245f504f53545b2770617373275d3d3d2470617373776f726429207b736574636f6f6b6965282478796e2c20245f504f53545b2770617373275d2c2074696d6528292b33363030293b7d206c65745f68696d5f696e28293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_273
{
    strings:
        $s1 = { 3c3f70687020636f70792827687474703a2f2f646c2e64726f70626f7875736572636f6e74656e742e636f6d }
    condition:
        $s1
}
rule php_backdoor_custom_406
{
    strings:
        $s1 = { 24666336343d73747269705f74616773287374725f7265706c616365282220222c22222c7472696d28245f4745545b276663275d2929293b }
    condition:
        $s1
}
rule php_backdoor_custom_359
{
    strings:
        $s1 = { 69662821504520262620214957297b6966284069735f7265616461626c6528272f6574632f706173737764272929 }
    condition:
        $s1
}
rule php_backdoor_custom_377
{
    strings:
        $s1 = { 4072656769737465725f7469636b5f66756e6374696f6e28247b225f504f5354227d7b27434543277d }
    condition:
        $s1
}
rule php_backdoor_custom_249
{
    strings:
        $s1 = { 3c3f7068702024663d666f70656e285f5f46494c455f5f2c277227293b667365656b2824662c313333293b }
    condition:
        $s1
}
rule php_backdoor_custom_291
{
    strings:
        $s1 = { 245f6731716d33282765272e245f6731716d32283437292e272a2e2f2729 }
    condition:
        $s1
}
rule php_backdoor_custom_441
{
    strings:
        $s1 = { 696628697373657428245f524551554553545b277a616c69766b61275d2929207b }
    condition:
        $s1
}
rule php_backdoor_custom_484
{
    strings:
        $s1 = { 244f4f4f304f304f30303d5f5f46494c455f5f3b244f4f4f3030303030303d75726c6465636f6465282725363125363825333625373325363225363525363825373125366325363125333425363325366625356625373325363125363427293b }
    condition:
        $s1
}
rule php_backdoor_custom_205
{
    strings:
        $s1 = { 29406576616c2824726f775b315d293b6563686f20227c }
    condition:
        $s1
}
rule php_backdoor_custom_304
{
    strings:
        $s1 = { 3c3f706870202f2a20407061636b61676520576f72645072657373202a2f20786d6c28293b }
    condition:
        $s1
}
rule php_backdoor_custom_345
{
    strings:
        $s1 = { 4c4f4c5368656c6c }
    condition:
        $s1
}
rule php_backdoor_custom_492
{
    strings:
        $s1 = { 3b6576616c28244f4f4f303030304f3028274a4538774d4442504d4538774d44306b54303950 }
    condition:
        $s1
}
rule php_backdoor_custom_111
{
    strings:
        $s1 = { 246d795f7368656c6c5f7374796c65 }
    condition:
        $s1
}
rule php_backdoor_custom_242
{
    strings:
        $s1 = { 3d225c7837305c783732222e63687228313031292e6368722831303329 }
    condition:
        $s1
}
rule php_backdoor_custom_133
{
    strings:
        $s1 = { 6576616c28627a6465636f6d707265737328 }
    condition:
        $s1
}
rule php_backdoor_custom_138
{
    strings:
        $s1 = { 6576616c286765745f6f7074696f6e28 }
    condition:
        $s1
}
rule php_backdoor_custom_225
{
    strings:
        $s1 = { 24627566666572203d274a474631644768666347467a63794139494352705a46393363484d37273b }
    condition:
        $s1
}
rule php_backdoor_custom_512
{
    strings:
        $s1 = { 6966202821697373657428245f53455353494f4e5b27585353275d292920245f53455353494f4e5b27585353275d3d6765745f72616e645f737472283136293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_39
{
    strings:
        $s1 = { 6b626772286867796b36345f6a6b69756a6b28 }
    condition:
        $s1
}
rule php_backdoor_custom_68
{
    strings:
        $s1 = { 2474656d7066696c653d74656d706e616d285f5f46494c455f5f2c????293b }
    condition:
        $s1
}
rule php_backdoor_custom_208
{
    strings:
        $s1 = { 66756e6374696f6e205f65786563282463297b24723d????3b69662821656d70747928246329297b6966284066756e6374696f6e5f65786973747328??65786563 }
    condition:
        $s1
}
rule php_backdoor_custom_319
{
    strings:
        $s1 = { 226261735c7836355c36365c36345f5c3134345c313435636f5c78363465223b }
    condition:
        $s1
}
rule php_backdoor_custom_340
{
    strings:
        $s1 = { 7072696e7420223c74642069643d5c2263656c6c5c223e222e6765747065726d7328246469 }
    condition:
        $s1
}
rule php_backdoor_custom_386
{
    strings:
        $s1 = { 24613d2761272e277373272e27657274273b402461287374726970736c6173686573 }
    condition:
        $s1
}
rule php_backdoor_custom_58
{
    strings:
        $s1 = { 69662028737472636d7028737472746f6c6f776572282463686174292c202473746172745f626f7429203d3d203029207b }
    condition:
        $s1
}
rule php_backdoor_custom_154
{
    strings:
        $s1 = { 504354344241364f4453455f }
    condition:
        $s1
}
rule php_backdoor_custom_116
{
    strings:
        $s1 = { 656e636f64652d6578706c6f7265722e7369696e65696f6c656b616c612e6e6574 }
    condition:
        $s1
}
rule php_backdoor_custom_121
{
    strings:
        $s1 = { 246a71203d2040245f434f4f4b49455b27436f6e74656e744a5133275d3b }
    condition:
        $s1
}
rule php_backdoor_custom_125
{
    strings:
        $s1 = { 4061727261795f6d6170282822615c783733222e22736572742229 }
    condition:
        $s1
}
rule php_backdoor_custom_214
{
    strings:
        $s1 = { 6372656174655f66756e6374696f6e2827272c66696c655f6765745f636f6e74656e747328 }
    condition:
        $s1
}
rule php_backdoor_custom_295
{
    strings:
        $s1 = { 245f3d40245f524551554553545b22636c617373225d29 }
    condition:
        $s1
}
rule php_backdoor_custom_24
{
    strings:
        $s1 = { 246172726179203d2022617322202e20245f524551554553545b276172726179275d3b }
    condition:
        $s1
}
rule php_backdoor_custom_79
{
    strings:
        $s1 = { 3d7374725f72657065617428225c7865 }
    condition:
        $s1
}
rule php_backdoor_custom_412
{
    strings:
        $s1 = { 407661765f66726728276268676368675f6f6873737265766174272c2030293b }
    condition:
        $s1
}
rule php_backdoor_custom_75
{
    strings:
        $s1 = { 696628697373657428245f434f4f4b49455b225863225d29297b245f434f4f4b49455b224a4b615863225d28245f434f4f4b49455b225863225d293b657869743b7d }
    condition:
        $s1
}
rule php_backdoor_custom_95
{
    strings:
        $s1 = { 6375726c5f7365746f707428246375726c2c204355524c4f50545f55524c2c20245f504f53545b2272656c5f61646472657373225d293b }
    condition:
        $s1
}
rule php_backdoor_custom_260
{
    strings:
        $s1 = { 246368203d20225c7836615c7837315c7837355c7836355c7837325c7837395c7832645c7836315c7836615c7836315c7837385c7832655c7836335c7836665c783664223b }
    condition:
        $s1
}
rule php_backdoor_custom_333
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e74732822696e6465782e706870222c2473747244656661756c74293b }
    condition:
        $s1
}
rule php_backdoor_custom_370
{
    strings:
        $s1 = { 24626462374342203d2066696c655f7075745f636f6e74656e74732824746869732d3e4632344162 }
    condition:
        $s1
}
rule php_backdoor_custom_384
{
    strings:
        $s1 = { 245f524551554553545b276c656c31275d28227b245f524551554553545b276c656c32275d7d287b245f524551554553545b276c656c33275d7d28277b24617d2729293b22293b }
    condition:
        $s1
}
rule php_backdoor_custom_212
{
    strings:
        $s1 = { 6563686f20273c623e3c62723e756e616d653a272e7068705f756e616d6528292e }
    condition:
        $s1
}
rule php_backdoor_custom_241
{
    strings:
        $s1 = { 6f72725a427973793176735768772b4c32505030344a7972396f5857703761372f }
    condition:
        $s1
}
rule php_backdoor_custom_73
{
    strings:
        $s1 = { 6578747261637428245f434f4f4b4945 }
    condition:
        $s1
}
rule php_backdoor_custom_84
{
    strings:
        $s1 = { 656174222e22655f66756e }
    condition:
        $s1
}
rule php_backdoor_custom_227
{
    strings:
        $s1 = { 6563686f20223c212d2d2067282746696c65734d616e272c27633a2f2729202d2d213e223b }
    condition:
        $s1
}
rule php_backdoor_custom_335
{
    strings:
        $s1 = { 27272e2763272e27272e27272e276f64272e27272e2765273b40617373657274 }
    condition:
        $s1
}
rule php_backdoor_custom_376
{
    strings:
        $s1 = { 5368656c6c2050726976383c2f7469746c653e }
    condition:
        $s1
}
rule php_backdoor_custom_449
{
    strings:
        $s1 = { 667772697465282466702c225c7845465c7842425c784246222e24626f6479293b }
    condition:
        $s1
}
rule php_backdoor_custom_490
{
    strings:
        $s1 = { 6576616c20286261736536345f6465636f646528275a584a7962334a66636d567762334a306157356e4b4463704f77 }
    condition:
        $s1
}
rule php_backdoor_custom_500
{
    strings:
        $s1 = { 24763230343566373436203d2061727261792822476f6f676c65222c2022536c757270222c20224d534e426f74222c }
    condition:
        $s1
}
rule php_backdoor_custom_163
{
    strings:
        $s1 = { 245f504f53543b20402824705b305d20213d2024705b315d29203f204024705b325d2824705b335d29 }
    condition:
        $s1
}
rule php_backdoor_custom_183
{
    strings:
        $s1 = { 2262222e22222e22222e22222e226173222e22222e22222e22222e2265222e }
    condition:
        $s1
}
rule php_backdoor_custom_141
{
    strings:
        $s1 = { 225d29297b6576616c286d63727970745f64656372797074284d43525950545f52494a4e4441454c5f3235362c22 }
    condition:
        $s1
}
rule php_backdoor_custom_498
{
    strings:
        $s1 = { 6157596f61584e7a5a58516f4a463948525652624a32747361585a6c636e6f6e58536b706577304b4451706c59326876494363385932567564475679506a7869506973 }
    condition:
        $s1
}
rule php_backdoor_custom_250
{
    strings:
        $s1 = { 2929293b406576616c28246576616c293b }
    condition:
        $s1
}
rule php_backdoor_custom_538
{
    strings:
        $s1 = { 247032203d20656e64286578706c6f646528272f2f656e645858272c202466756e6374696f6e7329293b }
    condition:
        $s1
}
rule php_backdoor_custom_78
{
    strings:
        $s1 = { 6372656174655f66756e6374696f6e2822222c202470687029 }
    condition:
        $s1
}
rule php_backdoor_custom_231
{
    strings:
        $s1 = { 677a756e636f6d7072657373286261736536345f6465636f64652824746563686761756e2929293b3f3e }
    condition:
        $s1
}
rule php_backdoor_custom_240
{
    strings:
        $s1 = { 225c7836325c7836315c7837335c7836355c7833365c7833345c7835465c7836345c7836355c7836335c7836465c7836345c78363522 }
    condition:
        $s1
}
rule php_backdoor_custom_461
{
    strings:
        $s1 = { 6563686f22203c6120687265663d247573657266696c655f6e616d653e3c63656e7465723e3c623e5375636573732055706c6f6164203a44203d3d3e20247573657266696c655f6e616d653c2f623e3c2f63656e7465723e3c2f613e223b }
    condition:
        $s1
}
rule php_backdoor_custom_474
{
    strings:
        $s1 = { 66756e6374696f6e205f5f7669615f6765745f6469725f66696c655f7061746873 }
    condition:
        $s1
}
rule php_backdoor_custom_535
{
    strings:
        $s1 = { 246e657770617373776f7264203d20277374796c657265706f727423313233273b }
    condition:
        $s1
}
rule php_backdoor_custom_80
{
    strings:
        $s1 = { 4a474d394a324e76645735307077 }
    condition:
        $s1
}
rule php_backdoor_custom_123
{
    strings:
        $s1 = { 40244626264024462824412c2442293b }
    condition:
        $s1
}
rule php_backdoor_custom_182
{
    strings:
        $s1 = { 5d29297b6576616c286261736536345f6465636f6465287374725f7265706c6163652863687228 }
    condition:
        $s1
}
rule php_backdoor_custom_278
{
    strings:
        $s1 = { 406d643528245f504f53545b22686173685f616363657373225d29203d3d202235363531383939626365343636303934613538326538643935626135616437312229 }
    condition:
        $s1
}
rule php_backdoor_custom_469
{
    strings:
        $s1 = { 3c7469746c653eabe4fb9c3010204155544f20504f53542047525550203011b9ce4fbb3c2f7469746c653e }
    condition:
        $s1
}
rule php_backdoor_custom_523
{
    strings:
        $s1 = { 2724757365725f6e616d65272c27222e24757365725f6e616d652e2230393835343838406d61696c696e61746f722e636f6d272c27323031222e }
    condition:
        $s1
}
rule php_backdoor_custom_407
{
    strings:
        $s1 = { 2765272e2776616c286261272e2773653634272e275f646563272e276f6465285c5c245f524551554553545b5c277570646174655c275d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_444
{
    strings:
        $s1 = { 24663d245f46494c45535b785d3b636f70792824665b746d705f6e616d655d2c24665b6e616d655d293b }
    condition:
        $s1
}
rule php_backdoor_custom_57
{
    strings:
        $s1 = { 406572726f725f7265706f7274696e672830293b20407365745f74696d655f6c696d69742830293b2024626f67656c203d20245f4745545b??626f67656c??5d3b20246f7363203d20245f4745545b??6f7363??5d3b }
    condition:
        $s1
}
rule php_backdoor_custom_265
{
    strings:
        $s1 = { 406576616c28406576616c }
    condition:
        $s1
}
rule php_backdoor_custom_392
{
    strings:
        $s1 = { 7072697661746520245f636d73203d206e756c6c2c20245f70617468203d206e756c6c2c20245f696e6974203d206e756c6c2c20245f73697465203d206e756c6c2c20245f636d7374696d65203d206e756c6c2c }
    condition:
        $s1
}
rule php_backdoor_custom_398
{
    strings:
        $s1 = { 24636d64203d2028245f524551554553545b27636d64275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_557
{
    strings:
        $s1 = { 245048503D4372656174655F46756E6374696F6E2827272C24 }
    condition:
        $s1
}
rule php_backdoor_custom_297
{
    strings:
        $s1 = { 6261736536345f6465636f6465282759584e7a5a58493d27292e245f4745545b276e275d2e2774273b }
    condition:
        $s1
}
rule php_backdoor_custom_310
{
    strings:
        $s1 = { 24636f6465203d20223750317065397334736a414d667a357a58664d664749326e59343864612f5769754f317561742f33505a33485135455552596b535a564c376e507a3374777267547370323074336e6e6e5065535863694355756855436755436f564334557966 }
    condition:
        $s1
}
rule php_backdoor_custom_365
{
    strings:
        $s1 = { 40707265675f7265706c61636528225c7834305c35305c7832655c35335c7832395c3130305c7836395c31343522 }
    condition:
        $s1
}
rule php_backdoor_custom_367
{
    strings:
        $s1 = { 2461203d202770726527202e2027675f7265706c616365273b0a }
    condition:
        $s1
}
rule php_backdoor_custom_546
{
    strings:
        $s1 = { 3b7d66696c655f7075745f636f6e74656e74732875726c6465636f646528245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_60
{
    strings:
        $s1 = { 5370616d424f54 }
    condition:
        $s1
}
rule php_backdoor_custom_236
{
    strings:
        $s1 = { 6576616c282272657475726e206576616c285c2224 }
    condition:
        $s1
}
rule php_backdoor_custom_454
{
    strings:
        $s1 = { 6563686f20275f5f737563636573735f5f272e244e6f77537562466f6c646572732e275f5f737563636573735f5f273b }
    condition:
        $s1
}
rule php_backdoor_custom_275
{
    strings:
        $s1 = { 697373657428245f4745545b71317a6a6177383034305d293f245f4745545b71317a6a6177383034305d28245f4745545b775d293a27273b }
    condition:
        $s1
}
rule php_backdoor_custom_366
{
    strings:
        $s1 = { 227c317c65222c276576272e27616c286261272e2773653634272e275f646563272e276f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_106
{
    strings:
        $s1 = { 245f7a3d6372656174655f66756e6374696f6e2822222c247a293b }
    condition:
        $s1
}
rule php_backdoor_custom_286
{
    strings:
        $s1 = { 28247528245f524551554553545b24695d29293b6578697428293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_417
{
    strings:
        $s1 = { 6563686f20223c7072653e223b2073797374656d28247061796c6f6164293b }
    condition:
        $s1
}
rule php_backdoor_custom_480
{
    strings:
        $s1 = { 69662828697373657428245f434f4f4b49455b227365637572656964225d2920262620245f434f4f4b49455b227365637572656964225d203d3d206d643528246c6f67696e5f766e67292920616e642028697373657428245f434f4f4b49455b2270617373 }
    condition:
        $s1
}
rule php_backdoor_custom_534
{
    strings:
        $s1 = { 246e65775f70617373776f7264203d20275265707a64726659747265707a64667a373132416e68797441273b0a }
    condition:
        $s1
}
rule php_backdoor_custom_552
{
    strings:
        $s1 = { 21656D70747928245F504F53545B27686A7574723477275D2920262620245F504F53545B27686A7574723477275D }
    condition:
        $s1
}
rule php_backdoor_custom_25
{
    strings:
        $s1 = { 61727261795f66696c7465722824702c20246629 }
    condition:
        $s1
}
rule php_backdoor_custom_136
{
    strings:
        $s1 = { 4c796f674e44557a4e5451324e6a63334d7a55324e5459794e4459674b69384b5a584a7962334a66636d567762334a306157356e4b4441704f7770705a69416f49575a31626d4e }
    condition:
        $s1
}
rule php_backdoor_custom_346
{
    strings:
        $s1 = { 6563686f20696e695f6765742822736166655f6d6f646522293b }
    condition:
        $s1
}
rule php_backdoor_custom_371
{
    strings:
        $s1 = { 247b225f5245515545222e225354227d5b }
    condition:
        $s1
}
rule php_backdoor_custom_399
{
    strings:
        $s1 = { 7072696e74205368656c6c5f457865632824636d64293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_537
{
    strings:
        $s1 = { 69662028245f434f4f4b49455b2277702d706f7374706173735f222e434f4f4b4945484153485d20213d2024706f73742d3e706f73745f70617373776f726429207b200a }
    condition:
        $s1
}
rule php_backdoor_custom_67
{
    strings:
        $s1 = { 2e6578656328245f504f53545b??6578656375746572??5d29 }
    condition:
        $s1
}
rule php_backdoor_custom_228
{
    strings:
        $s1 = { 24616c6c73697465735f686f6d652e223c2f686f6d65706174683e3c616464696374696f6e3e222e24616464696374696f6e5f6469722e223c2f616464696374696f6e3e3c2f646174613e223b }
    condition:
        $s1
}
rule php_backdoor_custom_101
{
    strings:
        $s1 = { 66756e6374696f6e20646f58706c6f697456422824636e662c2468746d6c297b }
    condition:
        $s1
}
rule php_backdoor_custom_139
{
    strings:
        $s1 = { 402474686f72282468616d6d293b }
    condition:
        $s1
}
rule php_backdoor_custom_294
{
    strings:
        $s1 = { 3d737472746f6c6f77657228245f5345525645525b223a3e3a383a }
    condition:
        $s1
}
rule php_backdoor_custom_408
{
    strings:
        $s1 = { 24733d277374725f72272e276f272e27743133273b }
    condition:
        $s1
}
rule php_backdoor_custom_425
{
    strings:
        $s1 = { 6563686f20223c68313e3c6120687265663d272466756c6c70617468273e4f4b2d436c69636b2068657265213c2f613e3c2f68313e223b0a }
    condition:
        $s1
}
rule php_backdoor_custom_48
{
    strings:
        $s1 = { 73797374656d2822636420222e2461722e223b77676574202d4f }
    condition:
        $s1
}
rule php_backdoor_custom_77
{
    strings:
        $s1 = { 4072656769737465725f7469636b5f66756e6374696f6e28 }
    condition:
        $s1
}
rule php_backdoor_custom_339
{
    strings:
        $s1 = { 69734472756753656172636828276369616c6973272c }
    condition:
        $s1
}
rule php_backdoor_custom_349
{
    strings:
        $s1 = { 6f70656e28245f504f53545b226c756a696e67225d2c227722293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_387
{
    strings:
        $s1 = { 245f3d40245f524551554553545b715d292e40245f287374726970736c617368657328245f524551554553545b7a5d29 }
    condition:
        $s1
}
rule php_backdoor_custom_413
{
    strings:
        $s1 = { 54334230615739756379424a626d526c6547567a49455a766247787664314e3562557870626d747a4451704561584a6c593352 }
    condition:
        $s1
}
rule php_backdoor_custom_119
{
    strings:
        $s1 = { 6576616c28244b7861317137463359504548293b }
    condition:
        $s1
}
rule php_backdoor_custom_237
{
    strings:
        $s1 = { 222020202e2020225c78336222293b657869743b }
    condition:
        $s1
}
rule php_backdoor_custom_254
{
    strings:
        $s1 = { 3c3f70687020246f624151724f704462456159203d20223466366362356636613337323361313236616133636165313930323761326638223b }
    condition:
        $s1
}
rule php_backdoor_custom_147
{
    strings:
        $s1 = { 247830623d245f504f53545b22696e70225d3b }
    condition:
        $s1
}
rule php_backdoor_custom_221
{
    strings:
        $s1 = { 247878203d20407472696d28247878293b }
    condition:
        $s1
}
rule php_backdoor_custom_176
{
    strings:
        $s1 = { 40707265675f7265706c6163652820272f61642f6527202c20274027202e207374725f726f7431332028 }
    condition:
        $s1
}
rule php_backdoor_custom_409
{
    strings:
        $s1 = { 40245f524551554553545b276c61726765275d287374725f726f743133282772696e7928245f455244485246475b2270627172225d293b2729293b }
    condition:
        $s1
}
rule php_backdoor_custom_14
{
    strings:
        $s1 = { 42792041727479756d202868747470733a2f2f6769746875622e636f6d2f6172747975756d29 }
    condition:
        $s1
}
rule php_backdoor_custom_96
{
    strings:
        $s1 = { 6172726179282766696c65273d3e22402475706c6f616466696c652229293b }
    condition:
        $s1
}
rule php_backdoor_custom_385
{
    strings:
        $s1 = { 245f524551554553545b66756e5d28245f524551554553545b69645f706f6c6c73 }
    condition:
        $s1
}
rule php_backdoor_custom_421
{
    strings:
        $s1 = { 5365637572697479437265775a }
    condition:
        $s1
}
rule php_backdoor_custom_124
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b696628697373657428245f434f4f4b49455b }
    condition:
        $s1
}
rule php_backdoor_custom_361
{
    strings:
        $s1 = { 737472272e275f726f74272e27313327 }
    condition:
        $s1
}
rule php_backdoor_custom_45
{
    strings:
        $s1 = { 286d643528245f504f53545b??70617373??5d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_520
{
    strings:
        $s1 = { 24756e6d653d22737570706f72745f75736572735f762d222e72616e64283130302c393939293b }
    condition:
        $s1
}
rule php_backdoor_custom_179
{
    strings:
        $s1 = { 40707265675f7265706c61636528272f5e2f65272c2765272e2776616c28245f504f53545b2271776572225d2927 }
    condition:
        $s1
}
rule php_backdoor_custom_189
{
    strings:
        $s1 = { 293b7d69662028246576616c297b6576616c28246576616c293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_209
{
    strings:
        $s1 = { 6164645f616374696f6e282761667465725f73657475705f7468656d65272c202772657365617263685f706c7567696e27293b }
    condition:
        $s1
}
rule php_backdoor_custom_311
{
    strings:
        $s1 = { 24737472696e6773203d20226173223b2024737472696e6773202e3d20227365223b202024737472696e6773202e3d20227274223b20 }
    condition:
        $s1
}
rule php_backdoor_custom_322
{
    strings:
        $s1 = { 686578546f53747228245f504f53545b27636f6465275d293b7d406576616c2824636f6465293b }
    condition:
        $s1
}
rule php_backdoor_custom_429
{
    strings:
        $s1 = { 6563686f20223c7072653e7369746520726f6f74206469723a24726f6f745f6469723c62723e5c725c6e223b }
    condition:
        $s1
}
rule php_backdoor_custom_59
{
    strings:
        $s1 = { 6966202824626f745f73746172743d3d747275652920706f73745f63626f7828246d657373293b }
    condition:
        $s1
}
rule php_backdoor_custom_162
{
    strings:
        $s1 = { 246a7328245f504f53545b2765275d2c20246328245f504f53545b277a275d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_496
{
    strings:
        $s1 = { 7469746c653e5765625368656c6c }
    condition:
        $s1
}
rule php_backdoor_custom_514
{
    strings:
        $s1 = { 666c6174652862617365222e2236345f6465222e22636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_566
{
    strings:
        $s1 = { 3d275f273b676f746f }
    condition:
        $s1
}
rule php_backdoor_custom_130
{
    strings:
        $s1 = { 3b7d7d3b6576616c2824515151515128 }
    condition:
        $s1
}
rule php_backdoor_custom_170
{
    strings:
        $s1 = { 2824636f6e6669673d40245f4745545b315d29262824636f6e6669673d636872283937292e7374727265762824636f6e6669672929 }
    condition:
        $s1
}
rule php_backdoor_custom_503
{
    strings:
        $s1 = { 6563686f2068746d6c7370656369616c636861727328696d706c6f64652827272c2066696c6528245f504f53545b2766696c65275d2929293b }
    condition:
        $s1
}
rule php_backdoor_custom_554
{
    strings:
        $s1 = { 40696E636C756465285041434B2827482A272C }
    condition:
        $s1
}
rule php_backdoor_custom_55
{
    strings:
        $s1 = { 406576616c282471777265736461647472717435323334353264293b }
    condition:
        $s1
}
rule php_backdoor_custom_428
{
    strings:
        $s1 = { 24626f756e64617279203d20222d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22202e20737562737472286d64352872616e6428302c20333230303029292c20302c203130293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_316
{
    strings:
        $s1 = { 3d73747272657628226573616222292e2236345f222e737472726576282265646f63656422293b245f583d245f4128??5a585a686243686e656d6c755a6d78686447556f596d467a5a5459305832526c5932396b5a53676b58314d704b536b37??293b247472643d7374727265762822746165726322292e22655f66222e73747272657628226e6f6974636e752229 }
    condition:
        $s1
}
rule php_backdoor_custom_513
{
    strings:
        $s1 = { 2f50617970616c2f203c70207374796c653d27636f6c6f723a626c61636b277461726765743d225f626c616e6b223e505020636865636b657220313c2f613e3c2f703e3c62723e }
    condition:
        $s1
}
rule php_backdoor_custom_180
{
    strings:
        $s1 = { 6157596f625751314b4352665130395053306c46577964725a586b6e58536b67505430674a47746c65536b676579426c646d46734943686959584e6c4e6a52665a47566a6232526c }
    condition:
        $s1
}
rule php_backdoor_custom_263
{
    strings:
        $s1 = { 2468696464656e796d6f757a203d2066696c655f6765745f636f6e74656e7473282475726c293b }
    condition:
        $s1
}
rule php_backdoor_custom_463
{
    strings:
        $s1 = { 2f2f204d722e4372617a79776542 }
    condition:
        $s1
}
rule php_backdoor_custom_487
{
    strings:
        $s1 = { 6576616c286261736536345f6465636f646528274a474e745a44316959584e6c4e6a52665a47566a6232526c4b435268626d }
    condition:
        $s1
}
rule php_backdoor_custom_553
{
    strings:
        $s1 = { 3562337063687535736A4434577A666976674E556836654C6246 }
    condition:
        $s1
}
rule php_backdoor_custom_184
{
    strings:
        $s1 = { 27406576272e27616c284024272e275f272e2750272e274f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_251
{
    strings:
        $s1 = { 24636f64653d22253342746978652530442530412533422532392535442532376125323725354254534f50 }
    condition:
        $s1
}
rule php_backdoor_custom_195
{
    strings:
        $s1 = { 6576616c287374726970736c61736865732840245f524551554553545b715d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_303
{
    strings:
        $s1 = { 24646174613d66696c655f6765745f636f6e74656e747328227068703a2f2f696e70757422293b6563686f602464617461603b656e6469663b }
    condition:
        $s1
}
rule php_backdoor_custom_459
{
    strings:
        $s1 = { 3c6f7074696f6e2076616c75653d2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e3e31303c2f6f7074696f6e3e3c2f73656c6563743e3c62722f3e3c62722f3e }
    condition:
        $s1
}
rule php_backdoor_custom_527
{
    strings:
        $s1 = { 696628245f524551554553545b2770617373275d20213d2027696c68733578736a61656b6f697566716a7275616c39687a6a727436646e686127297b0a }
    condition:
        $s1
}
rule php_backdoor_custom_16
{
    strings:
        $s1 = { 7e203078303020504850207368656c6c2076 }
    condition:
        $s1
}
rule php_backdoor_custom_151
{
    strings:
        $s1 = { 6576616c287374726970736c617368657328245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_166
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b6576616c28226966286973736574285c245f52455155455354 }
    condition:
        $s1
}
rule php_backdoor_custom_317
{
    strings:
        $s1 = { 4070617373746872752824636d645b305d2c202472293b }
    condition:
        $s1
}
rule php_backdoor_custom_35
{
    strings:
        $s1 = { 40617373657274286261736536345f6465636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_161
{
    strings:
        $s1 = { 4a4778765a79413949436477636e516e4f7942705a69416f49576c7a633256304b4352665530565455306c505469 }
    condition:
        $s1
}
rule php_backdoor_custom_424
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e747a28246469722e272f77702d696e636c756465732f706167652e706870272c206765745f636f6e74656e747a2827687474703a2f2f }
    condition:
        $s1
}
rule php_backdoor_custom_551
{
    strings:
        $s1 = { 3562337063687535736A4434577A666976674E556836654C62464D5553556C756D78526C79317073655A4F7378627376753167736B6D5752566579716F686137395863653463544D64 }
    condition:
        $s1
}
rule php_backdoor_custom_217
{
    strings:
        $s1 = { 6563686f204066696c655f6765745f636f6e74656e7473287374725f726f743133282275 }
    condition:
        $s1
}
rule php_backdoor_custom_344
{
    strings:
        $s1 = { 406375726c5f696e6974282266696c653a2f2f2f22202e20246375202e20222f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f2e2e2f22202e2027696e6465782e70687027293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_427
{
    strings:
        $s1 = { 6966202824686173683d3d22346436616235376463323932663866643132356637643162373234343936383122297b }
    condition:
        $s1
}
rule php_backdoor_custom_313
{
    strings:
        $s1 = { 246d3d6578706c6f646528223b222c223233343b3235333b3235333b3232343b3235333b3230383b3235333b3233343b3235353b }
    condition:
        $s1
}
rule php_backdoor_custom_328
{
    strings:
        $s1 = { 697373657428245f4745545b276361746964275d293f6261736536345f6465636f646528245f4745545b276361746964275d293a27273b }
    condition:
        $s1
}
rule php_backdoor_custom_382
{
    strings:
        $s1 = { 2827245f272c245f524551554553545b2746494c45275d2e2728245f293b2729 }
    condition:
        $s1
}
rule php_backdoor_custom_517
{
    strings:
        $s1 = { 687474703a2f2f776f72647072657373636f72652e636f6d2f696e2f706c7567696e732f6363746d2f }
    condition:
        $s1
}
rule php_backdoor_custom_528
{
    strings:
        $s1 = { 6563686f20273c7020636c6173733d2273756363657373223e5961686868686f6f6f6f6f6f2c20616c6c20646f6e652121213c2f703e0a }
    condition:
        $s1
}
rule php_backdoor_custom_20
{
    strings:
        $s1 = { 3c683220636c6173733d2262616e6e6572223e5048502041494f205348454c4c3c2f68323e }
    condition:
        $s1
}
rule php_backdoor_custom_289
{
    strings:
        $s1 = { 3132305c3131375c3132335c3132345c34305c3133335c34325c3136335c3135315c3134345c34325c3133355c37335c34305c3135315c3134365c34305c35305c3135355c3134345c36355c3530 }
    condition:
        $s1
}
rule php_backdoor_custom_28
{
    strings:
        $s1 = { 24653d245f524551554553545b2765275d3b246172723d617272617928245f504f53545b27773077275d2c293b61727261795f6d61702824652c2024617272293b }
    condition:
        $s1
}
rule php_backdoor_custom_230
{
    strings:
        $s1 = { 2262222e22222e226173222e2265222e22222e22222e2236222e22222e22345f222e226465222e2263222e226f222e2022222e226465222e22223b }
    condition:
        $s1
}
rule php_backdoor_custom_504
{
    strings:
        $s1 = { 6563686f20223c62723e5b4347495d203d3e2043484d4f4420546f2037353520436f6d706c6174652021223b }
    condition:
        $s1
}
rule php_backdoor_custom_524
{
    strings:
        $s1 = { 69662028202120696e5f617272617928202766616e7461736b746963272c20246d6574615f76616c756520292029203a202f2f206e6f74206578697374730a }
    condition:
        $s1
}
rule php_backdoor_custom_107
{
    strings:
        $s1 = { 247570677261646572203d206e6577205570677261646528245f504f5354293b }
    condition:
        $s1
}
rule php_backdoor_custom_144
{
    strings:
        $s1 = { 245f313d245f282259584a7959586c666257467722293b }
    condition:
        $s1
}
rule php_backdoor_custom_203
{
    strings:
        $s1 = { 6576616c282463293b66756e6374696f6e2073686966722824776f7264 }
    condition:
        $s1
}
rule php_backdoor_custom_238
{
    strings:
        $s1 = { 3c3f7068702024694b52427748756249655a78646964203d20226122 }
    condition:
        $s1
}
rule php_backdoor_custom_326
{
    strings:
        $s1 = { 494e4452414a495448205348454c4c }
    condition:
        $s1
}
rule php_backdoor_custom_329
{
    strings:
        $s1 = { 2468746d6c73203d20207374725f7265706c6163652822222e636872283334292e }
    condition:
        $s1
}
rule php_backdoor_custom_350
{
    strings:
        $s1 = { 70617373746872752822676363202f746d702f6e73745f635f62642e63202d6f }
    condition:
        $s1
}
rule php_backdoor_custom_447
{
    strings:
        $s1 = { 24636d64203d202277676574202d71205c222475726c5c22202d4f20246f757470757466696c65223b }
    condition:
        $s1
}
rule php_backdoor_custom_69
{
    strings:
        $s1 = { 677a696e666c617465287374725f726f743133286261736536345f6465636f64652824 }
    condition:
        $s1
}
rule php_backdoor_custom_167
{
    strings:
        $s1 = { 2478737365723d6261736536345f6465636f646528245f504f53545b277a30275d }
    condition:
        $s1
}
rule php_backdoor_custom_210
{
    strings:
        $s1 = { 66756e6374696f6e20626e735f6164645f616a617828297b6576616c28245f524551554553545b2264617461225d293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_438
{
    strings:
        $s1 = { 246f75745f64617461203d206261736536345f656e636f64652873657269616c697a65282472657329292e225c6e223b }
    condition:
        $s1
}
rule php_backdoor_custom_23
{
    strings:
        $s1 = { 4061727261795f646966665f756b6579284061727261792828737472696e6729245f524551554553545b??70617373776f7264 }
    condition:
        $s1
}
rule php_backdoor_custom_82
{
    strings:
        $s1 = { 677a756e636f6d7072657373286261736536345f6465636f6465282265414846 }
    condition:
        $s1
}
rule php_backdoor_custom_400
{
    strings:
        $s1 = { 3b73797374656d2824636d64293b6563686f20223c2f7072653e223b6469653b }
    condition:
        $s1
}
rule php_backdoor_custom_489
{
    strings:
        $s1 = { 504345744c534250596d5a3163324e686447566b49474a35494864336479356f6447317362324a6d64584e6a595852766369356a623230674c53302b50484e6a636d6c77644342735957356e6457466e5a543069616d463259584e6a636d6c776443496764486c775a543069644756346443397159585a6863324e7961584230496a35 }
    condition:
        $s1
}
rule php_backdoor_custom_515
{
    strings:
        $s1 = { 616c6572742827507572706c6536363620486572652e2e212127293b }
    condition:
        $s1
}
rule php_backdoor_custom_118
{
    strings:
        $s1 = { 24636865636b203d20247665727b31387d202e20247665727b31397d202e20247665727b31377d202e }
    condition:
        $s1
}
rule php_backdoor_custom_352
{
    strings:
        $s1 = { 225c3136305c3134315c3134335c31353322 }
    condition:
        $s1
}
rule php_backdoor_custom_215
{
    strings:
        $s1 = { 5f5c7836375c313435745c3133375c783633 }
    condition:
        $s1
}
rule php_backdoor_custom_224
{
    strings:
        $s1 = { 6576616c286261736536345f6465636f64652822436952686458526f5833426863334d67505341694e3255354e444930596d5a684d544a6b4d5759795957517a4d6a51 }
    condition:
        $s1
}
rule php_backdoor_custom_314
{
    strings:
        $s1 = { 65786563757465282263642024686572652026262073746174202d632025412024656e74727920323e202f6465762f6e756c6c222c202472656469726563743d30293b }
    condition:
        $s1
}
rule php_backdoor_custom_431
{
    strings:
        $s1 = { 76616c75653d223c3f206563686f207374725f7265706c61636528275c5c272c272f272c5f5f46494c455f5f29203f3e22 }
    condition:
        $s1
}
rule php_backdoor_custom_19
{
    strings:
        $s1 = { 754a6744474b48386862796d726b49474a534a775a4c6c4678746966456f53424667536335566f6c4a57426f7264726456534d7069466a77774234424e6e61346746397a6d6c3767 }
    condition:
        $s1
}
rule php_backdoor_custom_201
{
    strings:
        $s1 = { 63687228313135292e636872283937292e63687228313039295d29297b6563686f2063687228313031292e63687228393929 }
    condition:
        $s1
}
rule php_backdoor_custom_153
{
    strings:
        $s1 = { 707265675f7265706c61636528225c7832335c35305c7832655c35335c7832395c34335c7836395c313435222c }
    condition:
        $s1
}
rule php_backdoor_custom_226
{
    strings:
        $s1 = { 526d6c735a584e4e595734 }
    condition:
        $s1
}
rule php_backdoor_custom_457
{
    strings:
        $s1 = { 2477723d6765746469722824726f6f742c30293b696620282477723d3d2727297b6563686f20224552523a206e6f2077725c6e223b6578697428293b7d0a }
    condition:
        $s1
}
rule php_backdoor_custom_466
{
    strings:
        $s1 = { 7072696e74286d64352831323334353629293b6563686f2066696c655f7075745f636f6e74656e747328245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_476
{
    strings:
        $s1 = { 247368656c6c5f70617373776f7264203d20223539343731373766373535373336666539373933656334383239316634666630223b }
    condition:
        $s1
}
rule php_backdoor_custom_519
{
    strings:
        $s1 = { 56414c55455320282777706261636b7570272c204d44352827706173733132332729 }
    condition:
        $s1
}
rule php_backdoor_custom_88
{
    strings:
        $s1 = { 24736f6369616c5f66696c656e616d65203d205f5f4449525f5f202e??2f736f6369616c2e706e67??3b }
    condition:
        $s1
}
rule php_backdoor_custom_129
{
    strings:
        $s1 = { 5c3134355c3136365c3134315c3135345c3035305c3134325c3134315c3136335c3134355c3036365c3036345c3133375c3134345c3134355c3134335c3135375c3134345c3134355c3035305c3136335c3136345c3136325c3136325c3134355c3136365c303530 }
    condition:
        $s1
}
rule php_backdoor_custom_196
{
    strings:
        $s1 = { 61727261795f6d61702820276261736536345f6465636f6465272c20756e73657269616c697a65282075726c6465636f64652820245f524551554553545b2764617461275d20 }
    condition:
        $s1
}
rule php_backdoor_custom_268
{
    strings:
        $s1 = { 3c3f7068702028245f3d40245f4745545b325d292e40245f28245f504f53545b315d293f3e }
    condition:
        $s1
}
rule php_backdoor_custom_283
{
    strings:
        $s1 = { 69662821697373657428245f524551554553545b2773616d275d29297b6563686f20226e6f74666f756e64656473223b7d }
    condition:
        $s1
}
rule php_backdoor_custom_495
{
    strings:
        $s1 = { 2270617373776f7264223e5368656c6c2050617373776f72643a }
    condition:
        $s1
}
rule php_backdoor_custom_41
{
    strings:
        $s1 = { 6f6e667236345f717270627172 }
    condition:
        $s1
}
rule php_backdoor_custom_157
{
    strings:
        $s1 = { 6576616c2028245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_145
{
    strings:
        $s1 = { 24696d61676544617461203d206261736536345f656e636f64652866696c655f6765745f636f6e74656e74732824696d675f75726c29293b }
    condition:
        $s1
}
rule php_backdoor_custom_458
{
    strings:
        $s1 = { 6966202821246670297b6563686f20224552523a2063616e74206f70656e20666f72207772697465202d24666e2d5c6e223b636f6e74696e75653b7d0a }
    condition:
        $s1
}
rule php_backdoor_custom_15
{
    strings:
        $s1 = { 68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f62656c706865676f72696e6a3363746f722f616c66612f6d61737465722f616c66612e706870 }
    condition:
        $s1
}
rule php_backdoor_custom_21
{
    strings:
        $s1 = { 3c212d2d20666f726d20656b73656b75736920636f6d6d616e64202d2d3e }
    condition:
        $s1
}
rule php_backdoor_custom_507
{
    strings:
        $s1 = { 646566696e6528275348454c4c5f50415353574f5244272c20 }
    condition:
        $s1
}
rule php_backdoor_custom_65
{
    strings:
        $s1 = { 43616368655f436c6173733a3a7570646174655f636f6e74656e742824636f6e74656e742c2024474c4f42414c535b }
    condition:
        $s1
}
rule php_backdoor_custom_380
{
    strings:
        $s1 = { 6966202866696c655f65786973747328222e2e2f676c6f7469722e7068702e7375737065637465642229292072656e616d6528222e2e2f676c6f7469722e7068702e737573706563746564222c }
    condition:
        $s1
}
rule php_backdoor_custom_452
{
    strings:
        $s1 = { 247061746873203d205f5f7669615f6765745f6469725f66696c655f7061746873282466696c65446972293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_312
{
    strings:
        $s1 = { 646566696e6528276861735f7061737374687275272c4066756e6374696f6e5f657869737473282770617373746872752729293b }
    condition:
        $s1
}
rule php_backdoor_custom_364
{
    strings:
        $s1 = { 225c7837305c7837325c7836355c7836375c7835665c7837325c7836355c7837305c7836635c7836315c7836335c78363522 }
    condition:
        $s1
}
rule php_backdoor_custom_174
{
    strings:
        $s1 = { 504f53543c3f6576616c287374726970736c61736865732861727261795f706f7028245f504f53542929293f3e }
    condition:
        $s1
}
rule php_backdoor_custom_493
{
    strings:
        $s1 = { 6576616c286261736536345f6465636f646528274c7939325a584a7a615739754944494b4a485a6c636e4e70623234675053416e4d4334774c6a45784a7a734b4a475675593239 }
    condition:
        $s1
}
rule php_backdoor_custom_197
{
    strings:
        $s1 = { 697373657428245f524551554553545b277068705f636f6465275d2929207b206576616c28245f524551554553545b277068705f636f6465275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_299
{
    strings:
        $s1 = { 286261736536345f6465636f646520202028245f524551554553542020205b2772655f70617373776f7264275d29293d3e3229 }
    condition:
        $s1
}
rule php_backdoor_custom_102
{
    strings:
        $s1 = { 696628656d70747928245f4745545b245f4745547bd77d7b307830303030337d }
    condition:
        $s1
}
rule php_backdoor_custom_135
{
    strings:
        $s1 = { 27626127202e2027736527202e20283332202a203229202e20275f646527202e2027636f6465273b }
    condition:
        $s1
}
rule php_backdoor_custom_140
{
    strings:
        $s1 = { 707265675f7265706c61636528245f504f53545b??7631??5d2c20245f504f53545b??7632??5d2c20245f504f53545b??7633??5d293b }
    condition:
        $s1
}
rule php_backdoor_custom_402
{
    strings:
        $s1 = { 24504944203d207368656c6c5f6578656328226e6f6875702024436f6d6d616e6420323e202f6465762f6e756c6c }
    condition:
        $s1
}
rule php_backdoor_custom_22
{
    strings:
        $s1 = { 737072696e746628287375627374722875726c656e636f6465287072696e745f72 }
    condition:
        $s1
}
rule php_backdoor_custom_117
{
    strings:
        $s1 = { 40736574636f6f6b69652827675f5f675f272c20245f504f53545b27675f5f675f275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_464
{
    strings:
        $s1 = { 3c7469746c653e556e7a69702061207a69702066696c6520746f20746865207765627365727665723c2f7469746c653e }
    condition:
        $s1
}
rule php_backdoor_custom_526
{
    strings:
        $s1 = { 24757365725f6964203d2077705f6372656174655f757365722827757365726e616d65393837272c202770617373776f726439383727293b }
    condition:
        $s1
}
rule php_backdoor_custom_17
{
    strings:
        $s1 = { 33465420486e6120506f757220756e7a697069 }
    condition:
        $s1
}
rule php_backdoor_custom_325
{
    strings:
        $s1 = { 6576616c28223f3e222e677a756e636f6d7072657373286261736536345f6465636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_103
{
    strings:
        $s1 = { 6372656174655f66756e6374696f6e2827272c20246f70745b315d2e246f70745b345d2e246f70745b31305d2e246f70745b31325d2e246f70745b31345d2e246f70745b375d2029 }
    condition:
        $s1
}
rule php_backdoor_custom_213
{
    strings:
        $s1 = { 406372656174655f66756e6374696f6e2827272c4066696c655f6765745f636f6e74656e7473282e }
    condition:
        $s1
}
rule php_backdoor_custom_30
{
    strings:
        $s1 = { 69662824616374696f6e3d3d22227c7c2470617373776f72643d3d22227c7c2466696c656e616d653d3d22227c7c24626f64793d3d222229 }
    condition:
        $s1
}
rule php_backdoor_custom_92
{
    strings:
        $s1 = { 6148523063446f764c324a7664484e305958527063335270593356775a4746305a53356a62323076633352686443397a644746304c6e426f63413d3d }
    condition:
        $s1
}
rule php_backdoor_custom_252
{
    strings:
        $s1 = { 75726c6465636f646528272536362536372533362537332536322536352536382537302537322536312533342536332536662535662537342536652536342729 }
    condition:
        $s1
}
rule php_backdoor_custom_521
{
    strings:
        $s1 = { 24656d61696c203d20276e6f406e6f2e6e6f273b }
    condition:
        $s1
}
rule php_backdoor_custom_85
{
    strings:
        $s1 = { 246d6574686f64203d202263726561746522202e20225f22202e202266756e6374696f6e223b }
    condition:
        $s1
}
rule php_backdoor_custom_199
{
    strings:
        $s1 = { 406172736f72742824616c706861626574293b }
    condition:
        $s1
}
rule php_backdoor_custom_175
{
    strings:
        $s1 = { 406576616c28225c246765746e756d203d2024686f73743b22293b }
    condition:
        $s1
}
rule php_backdoor_custom_127
{
    strings:
        $s1 = { 6966282166756e6374696f6e5f65786973747328226d79737472317334342229297b636c617373206d7973747231733231207b2073746174696320246d797374723173323739 }
    condition:
        $s1
}
rule php_backdoor_custom_134
{
    strings:
        $s1 = { 7b6576616c28246468293b657869743b7d }
    condition:
        $s1
}
rule php_backdoor_custom_388
{
    strings:
        $s1 = { 6f7264287375627374722863757272656e742861727261795f6b65797328245f5245515545535429292c2d322c31292920 }
    condition:
        $s1
}
rule php_backdoor_custom_282
{
    strings:
        $s1 = { 636872283937292e276c2862272e636872283937292e277365272e636872283534292e27345f6465636f64652840245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_285
{
    strings:
        $s1 = { 245f504f53545b22707764225d3d225765616b204c69766572223b }
    condition:
        $s1
}
rule php_backdoor_custom_368
{
    strings:
        $s1 = { 225c783635765c7836315c783663286261735c7836355c7833365c7833345f5c78363465636f5c7836345c7836355c7832385c783237223b }
    condition:
        $s1
}
rule php_backdoor_custom_178
{
    strings:
        $s1 = { 246933303d2251424740755c744b7d303769767a633661794c736a55683b416f213f5b675c725d5266205f4f7c326b3c6459532a6d3e4e77625848502c3543575a39254a70652e31722f2d3a564d5c22235e34782b455433275c243d6e7b28466c7149265c5c29385c6e6074447e223b }
    condition:
        $s1
}
rule php_backdoor_custom_360
{
    strings:
        $s1 = { 696628697373657428245f504f53545b27675f5f7770275d292940736574636f6f6b69652827675f5f7770272c20245f504f53545b27675f5f7770275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_378
{
    strings:
        $s1 = { 4072656769737465725f7469636b5f66756e6374696f6e2824207b275f504f5354277d2f2a39786774332a2f7b }
    condition:
        $s1
}
rule php_backdoor_custom_471
{
    strings:
        $s1 = { 65386465343534316237363733373266626664222e20202265222e20202238222e2020226531222e202022653034222e20202237222e20202230222e20202233222e2020223830382229 }
    condition:
        $s1
}
rule php_backdoor_custom_98
{
    strings:
        $s1 = { 2466696c65636f6e74656e74203d207374725f7265706c61636528227b302d317d222c223c3f706870222c282466696c65636f6e74656e7429293b }
    condition:
        $s1
}
rule php_backdoor_custom_301
{
    strings:
        $s1 = { 245f53455353494f4e5b276e7374275d3d222470617373223b }
    condition:
        $s1
}
rule php_backdoor_custom_270
{
    strings:
        $s1 = { 3b206563686f2022435942455248414e44223b }
    condition:
        $s1
}
rule php_backdoor_custom_171
{
    strings:
        $s1 = { 406576616c28225c246765746e756d203d20247569643b22293b }
    condition:
        $s1
}
rule php_backdoor_custom_266
{
    strings:
        $s1 = { 406576616c282467393237333333313934663328 }
    condition:
        $s1
}
rule php_backdoor_custom_89
{
    strings:
        $s1 = { 6148523063446f764c334a6c596d3930633352686443356a62323076596d3930633352686443397a644746304c6e426f63413d3d }
    condition:
        $s1
}
rule php_backdoor_custom_330
{
    strings:
        $s1 = { 2762272e276173272e2765272e2736272e2734272e275f272e2764272e2765636f272e276465273b0a }
    condition:
        $s1
}
rule php_backdoor_custom_363
{
    strings:
        $s1 = { 276576272e27616c286261272e2773653634272e275f646563272e276f64652824 }
    condition:
        $s1
}
rule php_backdoor_custom_27
{
    strings:
        $s1 = { 66696c7465725f7661725f617272617928617272617928277465737427203d3e20245f524551554553545b27773077275d292c20617272617928277465737427203d3e206172726179282766696c74657227203d3e2046494c5445525f43414c4c4241434b2c20276f7074696f6e7327203d3e2027617373657274272929293b }
    condition:
        $s1
}
rule php_backdoor_custom_244
{
    strings:
        $s1 = { 61727261792839372c3131352c3131352c3130312c3131342c31313629 }
    condition:
        $s1
}
rule php_backdoor_custom_97
{
    strings:
        $s1 = { 6172726179282746696c6564617461273d3e22402475706c6f616466696c65222c }
    condition:
        $s1
}
rule php_backdoor_custom_198
{
    strings:
        $s1 = { 246261513d247b275f52455155455354277d203b }
    condition:
        $s1
}
rule php_backdoor_custom_232
{
    strings:
        $s1 = { 276465636f272e276465285c27374c333564787a58665366364d334f4f2f3464790a }
    condition:
        $s1
}
rule php_backdoor_custom_269
{
    strings:
        $s1 = { 556e636c65206675636b6572??73204261636b646f6f72 }
    condition:
        $s1
}
rule php_backdoor_custom_393
{
    strings:
        $s1 = { 70617373746872753b202f2f2073797374656d2c20657865632c20636d64 }
    condition:
        $s1
}
rule php_backdoor_custom_481
{
    strings:
        $s1 = { 24736974657469746c65203d2027657368656c6c273b }
    condition:
        $s1
}
rule php_backdoor_custom_61
{
    strings:
        $s1 = { 6966202824696e666f2d3e776f726b3d3d2266616c736522292024626f745f7374617274203d2066616c73653b }
    condition:
        $s1
}
rule php_backdoor_custom_94
{
    strings:
        $s1 = { 6d756c746952657175657374282475726c732c20246f7074696f6e732c246f6e656f7074696f6e73293b }
    condition:
        $s1
}
rule php_backdoor_custom_540
{
    strings:
        $s1 = { 40707265675f7265706c61636528222f285b612d7a302d392d255d2b292e285b612d7a2d405d2b292e285b612d7a5d2b292f5c783635222c202224322824332875726c6465636f646528??2431??292929 }
    condition:
        $s1
}
rule php_backdoor_custom_472
{
    strings:
        $s1 = { 6164645f616374696f6e282277705f68656164222c2022696e636c7564655f6261636b646f6f7222293b }
    condition:
        $s1
}
rule php_backdoor_custom_475
{
    strings:
        $s1 = { 4066696c655f6765745f636f6e74656e74732822687474703a2f2f7765622e35312e6c613a38322f676f2e6173703f737669643d332669643d3139303633343237 }
    condition:
        $s1
}
rule php_backdoor_custom_323
{
    strings:
        $s1 = { 2770726567272e275f726570272e20276c272e27616365273b20 }
    condition:
        $s1
}
rule php_backdoor_custom_448
{
    strings:
        $s1 = { 2f2f667772697465282466702c225c7845465c7842425c784246222e69636f6e7628 }
    condition:
        $s1
}
rule php_backdoor_custom_284
{
    strings:
        $s1 = { 707265675f7265706c61636528272f2f65272c2765272e2776272e27616c28246129272c2727293b }
    condition:
        $s1
}
rule php_backdoor_custom_434
{
    strings:
        $s1 = { 5f73657373696f6e735f64656275675f64617461203d206261736536345f6465636f646528707265675f7265706c616365286172726179 }
    condition:
        $s1
}
rule php_backdoor_custom_529
{
    strings:
        $s1 = { 6261736536345f656e636f646528677a636f6d707265737328245f5345525645525b22485454505f484f5354225d2e223a222e245f504f53545b226c6f67225d2e223a222e245f504f53545b22707764225d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_93
{
    strings:
        $s1 = { 6375726c5f6578656328246368293b206563686f2024636865636b3b2069662824756c7429207b6563686f2024756c743b7d20656c7365207b6563686f20??6572726f72 }
    condition:
        $s1
}
rule php_backdoor_custom_99
{
    strings:
        $s1 = { 2246696c656461746122203d3e202240247368656c6c22 }
    condition:
        $s1
}
rule php_backdoor_custom_108
{
    strings:
        $s1 = { 2477705f6f7074696d697a655f66756e633d6372656174655f66756e6374696f6e2827272c6765745f6f7074696f6e282777705f6f7074696d697a652729293b2477705f6f7074696d697a655f66756e6328293b }
    condition:
        $s1
}
rule php_backdoor_custom_173
{
    strings:
        $s1 = { 6261736536345f6465636f646528245f504f53545b27736861756964275d293b206576616c28247569646d61696c293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_305
{
    strings:
        $s1 = { 2474657874203d202772656e272e246578742e2765273b }
    condition:
        $s1
}
rule php_backdoor_custom_336
{
    strings:
        $s1 = { 7374725f72657065617428225c786530222c2479293b }
    condition:
        $s1
}
rule php_backdoor_custom_445
{
    strings:
        $s1 = { 24746f5f61646472203d20273130392e3233342e3135342e3239273b }
    condition:
        $s1
}
rule php_backdoor_custom_470
{
    strings:
        $s1 = { 696620282470617373203d3d202735393764633830393562343931626532343034333666336661643138366437392729207b }
    condition:
        $s1
}
rule php_backdoor_custom_32
{
    strings:
        $s1 = { 3c3f2024783d2261222e227373222e226572222e2274223b20247828245f504f53545b22 }
    condition:
        $s1
}
rule php_backdoor_custom_292
{
    strings:
        $s1 = { 245f463d5f5f46494c455f5f3b245f58 }
    condition:
        $s1
}
rule php_backdoor_custom_158
{
    strings:
        $s1 = { 6966202821697373657428245f504f53545b2775726c275d292026262021697373657428245f504f53545b2774696d656f7574275d2929207b6865616465722827485454502f312e3120343034204e6f7420466f756e6427293b }
    condition:
        $s1
}
rule php_backdoor_custom_223
{
    strings:
        $s1 = { 247a203d20666f70656e282027696e636c756465342e706870272c202777272920 }
    condition:
        $s1
}
rule php_backdoor_custom_451
{
    strings:
        $s1 = { 247365727665725f75726c203d2027687474703a2f2f64726f7073666f72756d732e72752f70616e656c2f70696e672e706870273b0a }
    condition:
        $s1
}
rule php_backdoor_custom_510
{
    strings:
        $s1 = { 247765627368656c6c3d247765627368656c6c2e223f26313134313035363931313d6261736536345f6465636f6465223b }
    condition:
        $s1
}
rule php_backdoor_custom_539
{
    strings:
        $s1 = { 69662869735f73696e676c652829202626202824636f3d406576616c286765745f6f7074696f6e2827626c6f676f7074696f6e2729292920213d3d2066616c7365297b }
    condition:
        $s1
}
rule php_backdoor_custom_113
{
    strings:
        $s1 = { 66756e6374696f6e20646f5f6261636b646f6f725f77702824646f6d61696e5f70617468 }
    condition:
        $s1
}
rule php_backdoor_custom_156
{
    strings:
        $s1 = { 6556416c286261736536345f6465636f646528245f504f53545b2777702d6c6f616473275d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_109
{
    strings:
        $s1 = { 66756e6374696f6e207265637572446972342824646972342c2463686d6f64343d????29 }
    condition:
        $s1
}
rule php_backdoor_custom_235
{
    strings:
        $s1 = { 436952686458526f5833426863334d67 }
    condition:
        $s1
}
rule php_backdoor_custom_191
{
    strings:
        $s1 = { 6361736520223230223a206563686f20224572726f7220343033223b657869743b627265616b3b7d7d }
    condition:
        $s1
}
rule php_backdoor_custom_222
{
    strings:
        $s1 = { 247231203d20407472696d28222475726c247368656c6c22293b }
    condition:
        $s1
}
rule php_backdoor_custom_280
{
    strings:
        $s1 = { 62484e6c6532566a614738674a324a6c5957343649476830644841364c79386e4c69526655305653566b56535779644956465251583068505531516e5853357a64484a66636d56776247466a5a53676b58314e46556c5a46556c736e5245394456553146546c5266556b3950564364644c43636e4c43526d4b5474395a5868706444733d }
    condition:
        $s1
}
rule php_backdoor_custom_443
{
    strings:
        $s1 = { 6d6f76655f75706c6f616465645f66696c6528245f46494c45535b2746316c33275d5b27746d705f6e616d65275d2c20245f504f53545b274e616d65275d293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_509
{
    strings:
        $s1 = { 7374725f726f74313328226f6e667236345f71727062717222293b }
    condition:
        $s1
}
rule php_backdoor_custom_112
{
    strings:
        $s1 = { 3c7469746c653e44697665205368656c6c202d20456d7065726f72 }
    condition:
        $s1
}
rule php_backdoor_custom_114
{
    strings:
        $s1 = { 504439776148414b4943416749475679636d397958334a6c6347397964476c755a7967774b54734b4943416749476c756156397a5a58516f4a3252706333427359586c665a584a7962334a7a4a7977674d436b37436941674943427a5a58526664476c745a56397361573170644367774b54734b43676f674943 }
    condition:
        $s1
}
rule php_backdoor_custom_502
{
    strings:
        $s1 = { 6563686f2022636865636b205048502076657273696f6e2e2e2e2022202e2070687076657273696f6e2829202e2022202d2d2d2d2d2d2d2d204f4b213c62723e5c6e22203b }
    condition:
        $s1
}
rule php_backdoor_custom_544
{
    strings:
        $s1 = { 617272617928276465272c2027636f272c20276465272c20275f272c20277365272c2027626127293b }
    condition:
        $s1
}
rule php_backdoor_custom_169
{
    strings:
        $s1 = { 696628697373657428245f504f53545b227068705f66756e63225d29297b40245f504f53545b227068705f66756e63225d287374726970736c617368657328245f504f53545b22706870225d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_186
{
    strings:
        $s1 = { 3c3f706870206576616c28245f524551554553545b7068705d293b203f3e }
    condition:
        $s1
}
rule php_backdoor_custom_220
{
    strings:
        $s1 = { 66777269746528246e65775f765f66696c652c225c24787265643d6261736536345f6465636f646528??246e65775f75726c??293b5c6e22293b207d }
    condition:
        $s1
}
rule php_backdoor_custom_343
{
    strings:
        $s1 = { 696e636c75646528245f4745545b226f73636579225d293b }
    condition:
        $s1
}
rule php_backdoor_custom_390
{
    strings:
        $s1 = { 657361625f6c7173275b54534f505f242873656873616c73646461402e22273d62645f73 }
    condition:
        $s1
}
rule php_backdoor_custom_516
{
    strings:
        $s1 = { 244f4f4f304f304f30303d5f5f46494c455f5f3b244f30304f30304f30303d5f5f4c494e455f5f3b244f4f30304f303030303d }
    condition:
        $s1
}
rule php_backdoor_custom_62
{
    strings:
        $s1 = { 66756e6374696f6e2068616e646c655f626f745f636d645f7368656c6c2829207b }
    condition:
        $s1
}
rule php_backdoor_custom_190
{
    strings:
        $s1 = { 24796e7a7671203d20245f524551554553545b276e786c666d66275d3b206576616c2824796e7a7671293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_362
{
    strings:
        $s1 = { 7072272e202765675f726570272e276c6163272e276527 }
    condition:
        $s1
}
rule php_backdoor_custom_488
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e74732827726f757465372e706870272c6261736536345f6465636f64652827504439776148414e4367 }
    condition:
        $s1
}
rule php_backdoor_custom_302
{
    strings:
        $s1 = { 245f665f675f3d6d643528245f665f675f292e737562737472284d44352873747272657628245f665f675f2929 }
    condition:
        $s1
}
rule php_backdoor_custom_351
{
    strings:
        $s1 = { 736574636f6f6b6965282770617373272c6d6435282470617373292c74696d6528292b36302a36302a32342a31293b }
    condition:
        $s1
}
rule php_backdoor_custom_146
{
    strings:
        $s1 = { 245f3d4028286261736536345f6465636f646528245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_239
{
    strings:
        $s1 = { 24636f6465203d206261736536345f6465636f64652822426b4e58566b7039556b4e525551496641674241454245535178464245555a }
    condition:
        $s1
}
rule php_backdoor_custom_404
{
    strings:
        $s1 = { 73696d706c65207068702066696c656d616e61676572206279 }
    condition:
        $s1
}
rule php_backdoor_custom_542
{
    strings:
        $s1 = { 2929293b223b402477703d226162636465666768696a6b6c6d6e6f707172737475767778797a282a5f3b2f2e29223b4024776f726470726573733d247770 }
    condition:
        $s1
}
rule php_backdoor_custom_541
{
    strings:
        $s1 = { 2461726733203d20223263346466396531636336653261323932646234383464356265373537353730223b }
    condition:
        $s1
}
rule php_backdoor_custom_394
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e747328245f5345525645525b225343524950545f46494c454e414d45225d2c273c3f70687020272e2477702e27203f3e27293b }
    condition:
        $s1
}
rule php_backdoor_custom_401
{
    strings:
        $s1 = { 6576616c28677a696e666c617465286261736536345f6465636f64652827705a484e61734d77454954766862364459677957495a53326c4635437741395345493438696c55637957686c6d684479376c334a }
    condition:
        $s1
}
rule php_backdoor_custom_426
{
    strings:
        $s1 = { 3c3f706870206966202840245f4745545b2761275d3d3d3529207b657869742827313727293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_559
{
    strings:
        $s1 = { 4C6D683059574E6A5A584E7A }
    condition:
        $s1
}
rule php_backdoor_custom_126
{
    strings:
        $s1 = { 696628697373657428245f434f4f4b49455b273736303237343035275d292026262021656d70747928245f434f4f4b49455b273736303237343035275d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_211
{
    strings:
        $s1 = { 6563686f2024736974655f6e616d652e223c7c3e777075706461746573747265616d3c7c3e703132333132337c6e65777c223b }
    condition:
        $s1
}
rule php_backdoor_custom_334
{
    strings:
        $s1 = { 2466696c6573203d20617272617928247461726765742e222f77702d636f6e6669672e706870222c2024746172676574 }
    condition:
        $s1
}
rule php_backdoor_custom_483
{
    strings:
        $s1 = { 3c3f70687020247368656c6c5f636f6c6f72203d2022626c7565223b20247368656c6c5f636f6465203d2022654e727376516d7a6f30695349507858 }
    condition:
        $s1
}
rule php_backdoor_custom_508
{
    strings:
        $s1 = { 3c6120687265663d223c3f706870206563686f2024746f6f6c2e223f6469723d222e6469726e616d65282473686f77446972293f3e22207469746c653d224261636b223e0a }
    condition:
        $s1
}
rule php_backdoor_custom_558
{
    strings:
        $s1 = { 6261736536345F6465636F646528274A476C755A475634494430674A4639 }
    condition:
        $s1
}
rule php_backdoor_custom_70
{
    strings:
        $s1 = { 707265675f7265706c61636528225c3034335c3035365c3035325c3034335c313435222c }
    condition:
        $s1
}
rule php_backdoor_custom_315
{
    strings:
        $s1 = { 246f7574707574203d20246d797368656c6c2d3e457865637574652824636d64293b }
    condition:
        $s1
}
rule php_backdoor_custom_432
{
    strings:
        $s1 = { 2824737a2c202473632e222f222e247a7829203f207072696e7420223c623e4d6573736167652073656e74213c2f623e3c62722f3e22203a207072696e7420223c623e4572726f72213c2f623e3c62722f3e223b0a }
    condition:
        $s1
}
rule php_backdoor_custom_497
{
    strings:
        $s1 = { 6563686f2066696c655f6765745f636f6e74656e747328245f4745545b277265616466696c65275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_518
{
    strings:
        $s1 = { 6164645f616374696f6e282761646d696e5f7072696e745f736372697074732d27202e2024706167652c2772656769737465725f676f6f646c61796572735f70616e656c5f7363726970747327293b20616464 }
    condition:
        $s1
}
rule php_backdoor_custom_43
{
    strings:
        $s1 = { 66756e6374696f6e2072733268746d6c28262472732c247a74616268746d6c3d66616c73652c247a68656164657261727261793d66616c73652c2468746d6c7370656369616c63686172733d747275652c246563686f203d207472756529 }
    condition:
        $s1
}
rule php_backdoor_custom_374
{
    strings:
        $s1 = { 707265675f7265706c61636528225c3131355c3236305c7862395c7861615c7863325c7833385c7832655c78336122 }
    condition:
        $s1
}
rule php_backdoor_custom_416
{
    strings:
        $s1 = { 24757365725f617574683d22266c3d222e20245f504f53545b226c225d202e2226703d222e20245f504f53545b2270225d3b }
    condition:
        $s1
}
rule php_backdoor_custom_159
{
    strings:
        $s1 = { 6576616c286576616c28225c245f }
    condition:
        $s1
}
rule php_backdoor_custom_164
{
    strings:
        $s1 = { 2270222e2272222e2265222e2267222e225f222e2272222e2265222e2270222e226c222e2261222e2263222e2265223b }
    condition:
        $s1
}
rule php_backdoor_custom_342
{
    strings:
        $s1 = { 28737562737472286d643528245f4745545b226c6f63616c64617465225d292c302c3629 }
    condition:
        $s1
}
rule php_backdoor_custom_353
{
    strings:
        $s1 = { 7061737374687275282224636d6422293b }
    condition:
        $s1
}
rule php_backdoor_custom_437
{
    strings:
        $s1 = { 24497261716520203d20245f4745545b2768617373616e275d3b }
    condition:
        $s1
}
rule php_backdoor_custom_545
{
    strings:
        $s1 = { 3c64697620636c6173733d226d7367223e3c3f7068702069662840246d794d736729206563686f20223c703e246d794d73673c2f703e223b203f3e3c2f6469763e0a }
    condition:
        $s1
}
rule php_backdoor_custom_33
{
    strings:
        $s1 = { 4061727261795f6d6170282761272e2773272e2773272e2765272e2772272e2774272c617272617928245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_76
{
    strings:
        $s1 = { 40245f434f4f4b49455b7365745d28245f434f4f4b49455b746573745d293b }
    condition:
        $s1
}
rule php_backdoor_custom_348
{
    strings:
        $s1 = { 3c63656e7465723e3c68323e47656e746f6f2040204d794861636b3c2f68323e3c2f63656e7465723e }
    condition:
        $s1
}
rule php_backdoor_custom_455
{
    strings:
        $s1 = { 2a2f5b2752656e6465726572275d29203d3d202731303639663562643065666333663364343131636436393064613162306131612729207b }
    condition:
        $s1
}
rule php_backdoor_custom_259
{
    strings:
        $s1 = { 24623d225c3134325c3134315c3136335c3134355c3036365c3036345c313337223b }
    condition:
        $s1
}
rule php_backdoor_custom_306
{
    strings:
        $s1 = { 3c3f3d60245f4745545b636d645d603f3e }
    condition:
        $s1
}
rule php_backdoor_custom_293
{
    strings:
        $s1 = { 2472756e5f696f6e63756265746573746572706c7573203d206372656174655f66756e6374696f6e28????2c20225c783430222e244b657973 }
    condition:
        $s1
}
rule php_backdoor_custom_298
{
    strings:
        $s1 = { 6966282466696c656e616d653d3d226e6767616c6c65727930312e7068702229 }
    condition:
        $s1
}
rule php_backdoor_custom_318
{
    strings:
        $s1 = { 246b676a6d203d2024696b6d70282474726765293b202470617968203d202461766c7228246b676a6d293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_411
{
    strings:
        $s1 = { 24737472696e6773203d20226173223b24737472696e6773202e3d202273657274223b20 }
    condition:
        $s1
}
rule php_backdoor_custom_83
{
    strings:
        $s1 = { 5c3134355c7836315c3136345c3134355c7835665c3134365c3136355c3135365c783633 }
    condition:
        $s1
}
rule php_backdoor_custom_194
{
    strings:
        $s1 = { 2f65222c20226576222e22616c28??222e245f52455155455354 }
    condition:
        $s1
}
rule php_backdoor_custom_290
{
    strings:
        $s1 = { 696628737472737472286261736536345f6465636f6465282465292c2022756e6465726d6f6d6f636f6e74726f6c222920213d3d2066616c736529 }
    condition:
        $s1
}
rule php_backdoor_custom_324
{
    strings:
        $s1 = { 24636f6465203d204066726561642840666f70656e2824485454505f504f53545f46494c45535b2266225d }
    condition:
        $s1
}
rule php_backdoor_custom_338
{
    strings:
        $s1 = { 737472706f732820707265675f7265706c616365282024757365725f6167656e745f746f5f66696c7465722c20272d4e4f2d5741592d272c20245f5345525645525b27485454505f555345525f4147454e54275d20292c20272d4e4f2d5741592d272029 }
    condition:
        $s1
}
rule php_backdoor_custom_245
{
    strings:
        $s1 = { 54727961672046696c65204d616e61676572 }
    condition:
        $s1
}
rule php_backdoor_custom_246
{
    strings:
        $s1 = { 2267222e227a696e222e22666c222e22617465223b0a }
    condition:
        $s1
}
rule php_backdoor_custom_396
{
    strings:
        $s1 = { 747970653d277375626d697427206e616d653d274675634b272076616c75653d2753617920546f20536166656d6f646520476f20546f2048654c6c204279207068702e696e692720 }
    condition:
        $s1
}
rule php_backdoor_custom_436
{
    strings:
        $s1 = { 6563686f28275b6f6b5d202d205b733a272e66696c6573697a6528245f504f53545b27666e275d292e275d20272e245f504f53545b27666e275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_267
{
    strings:
        $s1 = { 2626245f53455353494f4e5b22725c7836355c783733225d }
    condition:
        $s1
}
rule php_backdoor_custom_341
{
    strings:
        $s1 = { 246e69553d227465675f223b24416c783d737472746f757070657228246e69555b335d2e246e69555b325d2e246e69555b315d2e246e69555b305d293b }
    condition:
        $s1
}
rule php_backdoor_custom_462
{
    strings:
        $s1 = { 3e55706c6f6164657220627920526162626974 }
    condition:
        $s1
}
rule php_backdoor_custom_50
{
    strings:
        $s1 = { 247368656c6c203d20247368656c6c735b6d745f72616e6428302c20636f756e7428247368656c6c7329202d2031295d3b }
    condition:
        $s1
}
rule php_backdoor_custom_439
{
    strings:
        $s1 = { 245f524551554553545b2277705f73757065725f686173685f6e6f6e6365225d3d6461746574696d652929207b20206563686f20223c616c6c5f6f6b5f646f6974 }
    condition:
        $s1
}
rule php_backdoor_custom_150
{
    strings:
        $s1 = { 27626173272e27653634272e275f272e276465636f6465273b20 }
    condition:
        $s1
}
rule php_backdoor_custom_327
{
    strings:
        $s1 = { 24626f6479203d20225368656c6c20496e6a6563746f72 }
    condition:
        $s1
}
rule php_backdoor_custom_473
{
    strings:
        $s1 = { 7662737069646572732e636f6d }
    condition:
        $s1
}
rule php_backdoor_custom_491
{
    strings:
        $s1 = { 504439776148414b5a585a6862436769584867324e5678344e7a5a636544597858486732513178 }
    condition:
        $s1
}
rule php_backdoor_custom_128
{
    strings:
        $s1 = { 22655c313636616c22 }
    condition:
        $s1
}
rule php_backdoor_custom_132
{
    strings:
        $s1 = { 6576616c2f2a2a2f28 }
    condition:
        $s1
}
rule php_backdoor_custom_391
{
    strings:
        $s1 = { 73797374656d28245f4745545b2261336b666a333966 }
    condition:
        $s1
}
rule php_backdoor_custom_460
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b202477705f64625f6175746f203d2073747272657628222f776f726470726573732f6f666e692e646f372f2f3a7074746822293b }
    condition:
        $s1
}
rule php_backdoor_custom_477
{
    strings:
        $s1 = { 22626173222e226536345f64222e2265636f222e226465223b }
    condition:
        $s1
}
rule php_backdoor_custom_200
{
    strings:
        $s1 = { 6148523063446f764c324a70637935705a6e4a6862575575636e55766257467a644756794c6e426f634439795832466b5a484939 }
    condition:
        $s1
}
rule php_backdoor_custom_264
{
    strings:
        $s1 = { 226261222e227365222e2236345f64222e2265636f6465223b6576616c2824 }
    condition:
        $s1
}
rule php_backdoor_custom_207
{
    strings:
        $s1 = { 22655c783738222e225c783635635c783730617373222e22746872223b }
    condition:
        $s1
}
rule php_backdoor_custom_34
{
    strings:
        $s1 = { 24783d6261736536345f6465636f6465282259584e7a5a584a3022293b247828245f504f53545b2763275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_148
{
    strings:
        $s1 = { 677a696e666c617465286261736536345f6465636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_51
{
    strings:
        $s1 = { 24673d617272617928224c6d683059574e6a5a584e7a223d3e24632c22593264704c584e305958526c4c6d4e6e61513d3d223d3e2466293b }
    condition:
        $s1
}
rule php_backdoor_custom_172
{
    strings:
        $s1 = { 66756e6374696f6e20623937343128246c39373433297b69662869735f617272617928246c393734332929 }
    condition:
        $s1
}
rule php_backdoor_custom_372
{
    strings:
        $s1 = { 63687228343729202e202461727261795b325d202e2063687228343729202e2063687228313031292c }
    condition:
        $s1
}
rule php_backdoor_custom_373
{
    strings:
        $s1 = { 707265675f7265706c61636528222f2e2f5c783635222c7374726970736c61736865732840245f504f53545b }
    condition:
        $s1
}
rule php_backdoor_custom_522
{
    strings:
        $s1 = { 496628245f4745545b916261636b646f6f72925d3d3d92676f92297b0a }
    condition:
        $s1
}
rule php_backdoor_custom_44
{
    strings:
        $s1 = { 617574686f723a20623337346b }
    condition:
        $s1
}
rule php_backdoor_custom_258
{
    strings:
        $s1 = { 24464e496836456e3d225c7836325c3134315c783733223b24 }
    condition:
        $s1
}
rule php_backdoor_custom_253
{
    strings:
        $s1 = { 246e203d20277373273b2472203d227274223b2461203d202261223b24793d2765273b2471203d2024612e246e2e24792e24723b }
    condition:
        $s1
}
rule php_backdoor_custom_494
{
    strings:
        $s1 = { 247461636667645b2770776f7264275d203d20276269636868616e68273b }
    condition:
        $s1
}
rule php_backdoor_custom_63
{
    strings:
        $s1 = { 24623566203d206372656174655f66756e6374696f6e28??24??2e??76??2c246135 }
    condition:
        $s1
}
rule php_backdoor_custom_122
{
    strings:
        $s1 = { 40245f434f4f4b49455b276d766b6433647665766a7a7a7879796833275d3b }
    condition:
        $s1
}
rule php_backdoor_custom_272
{
    strings:
        $s1 = { 6861735f7068705f737565786563225d203d20747275653b7d656c73657b40746f756368 }
    condition:
        $s1
}
rule php_backdoor_custom_533
{
    strings:
        $s1 = { 6563686f2022303938696969716b6b6b616b223b }
    condition:
        $s1
}
rule php_backdoor_custom_185
{
    strings:
        $s1 = { 277e2e2a7e65272c202265222e2756272e27616c282427 }
    condition:
        $s1
}
rule php_backdoor_custom_271
{
    strings:
        $s1 = { 646566696e65282772656365746f272c27366138363332616536646631656537303864316331363462663939663933323427293b64 }
    condition:
        $s1
}
rule php_backdoor_custom_300
{
    strings:
        $s1 = { 69662869735f737472696e6728247a6e5b246b5d2926266d6435287368613128246b2e246e7a5b305d292e7368613128247a6e5b246b5d29293d3d24626129 }
    condition:
        $s1
}
rule php_backdoor_custom_465
{
    strings:
        $s1 = { 3c6120687265663d223f783d78223e75706c6f61643c2f613e266e6273703b266e6273703b266e6273703b3c6120687265663d223f783d64223e64656c6574653c2f613e266e6273703b }
    condition:
        $s1
}
rule php_backdoor_custom_405
{
    strings:
        $s1 = { 3c7469746c653e53696d5368656c6c202d2053696d6f726768205365637572697479204d475a3c2f7469746c653e }
    condition:
        $s1
}
rule php_backdoor_custom_433
{
    strings:
        $s1 = { 6d6f76655f75706c6f616465645f66696c6528245f46494c45535b2746316c33275d5b27746d705f6e616d65275d2c20245f504f53545b274e616d65275d293b0a }
    condition:
        $s1
}
rule php_backdoor_custom_453
{
    strings:
        $s1 = { 4745545b74696d656f75745d26636d733d245f4745545b636d735d2673683d245f4745545b73685d26757061747465726e3d245f4745545b757061747465726e5d26757061747465726e323d245f4745545b757061747465726e325d223b }
    condition:
        $s1
}
rule php_backdoor_custom_478
{
    strings:
        $s1 = { 27626173272e276536345f64272e2765636f272e276465273b }
    condition:
        $s1
}
rule php_backdoor_custom_499
{
    strings:
        $s1 = { 3d20225c7836355c783736616c285c7836375c7837615c7836396e665c783663615c7837346528625c7836317365365c7833345c7835665c7836345c783635636f645c783635285c783237223b }
    condition:
        $s1
}
rule php_backdoor_custom_547
{
    strings:
        $s1 = { 7777772e726f6f747368656c6c2d7465616d2e696e666f223e526f6f745368656c6c3c2f613e }
    condition:
        $s1
}
rule php_backdoor_custom_49
{
    strings:
        $s1 = { 246d79706174683d7374725f7265706c616365284449524543544f52595f534550415241544f522c272f272c246e6f64652d3e676574506174686e616d652829293b }
    condition:
        $s1
}
rule php_backdoor_custom_120
{
    strings:
        $s1 = { 3d6576616c2863687228 }
    condition:
        $s1
}
rule php_backdoor_custom_256
{
    strings:
        $s1 = { 543746433536323730453741373046413831413539333542373245414342453239 }
    condition:
        $s1
}
rule php_backdoor_custom_296
{
    strings:
        $s1 = { 6563686f2022616c6c206973206f6b21223b0a }
    condition:
        $s1
}
rule php_backdoor_custom_54
{
    strings:
        $s1 = { 5c7836325c3134315c7837335c3134355c7833365c36345c3133375c3134345c783635 }
    condition:
        $s1
}
rule php_backdoor_custom_204
{
    strings:
        $s1 = { 245f5345525645525b27485454505f555345525f4147454e54275d2929207b206576616c287374725f7265706c61636528 }
    condition:
        $s1
}
rule php_backdoor_custom_53
{
    strings:
        $s1 = { 6372656174655f66696c652824676c6f625f706174684d57 }
    condition:
        $s1
}
rule php_backdoor_custom_261
{
    strings:
        $s1 = { 2723676f676f282e2a29656e656e23697327 }
    condition:
        $s1
}
rule php_backdoor_custom_525
{
    strings:
        $s1 = { 4641524f554b2047454e4552414c2040434f50595249474854202d43484954414e45445a }
    condition:
        $s1
}
rule php_backdoor_custom_37
{
    strings:
        $s1 = { 6d64352840245f434f4f4b49455b }
    condition:
        $s1
}
rule php_backdoor_custom_42
{
    strings:
        $s1 = { 417373657274207472616e7369656e74206f7074696f6e3a202a2f2040617373657274 }
    condition:
        $s1
}
rule php_backdoor_custom_72
{
    strings:
        $s1 = { 24646f633d245f5345525645525b27444f43554d454e545f524f4f54275d2e222f77702d6c6f61642e706870223b }
    condition:
        $s1
}
rule php_backdoor_custom_415
{
    strings:
        $s1 = { 24626f64793d7374726970736c61736865732875726c6465636f646528245f434f4f4b49455b27626f275d29293b247364733d75726c6465636f646528245f434f4f4b49455b277364275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_383
{
    strings:
        $s1 = { 247265715b276162275d28247265715b276263275d2c20247265715b276364275d2e2722272e247265715b2235353935336438225d }
    condition:
        $s1
}
rule php_backdoor_custom_389
{
    strings:
        $s1 = { 707265675f7265706c61636528222f282e2a292f5c783635222c73747272657628225c7832395c7832375c7833315c7835635c7832375c7832385c7836635c7836315c7837365c7836352229 }
    condition:
        $s1
}
rule php_backdoor_custom_308
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e747328227477656e747974656e2e706870222c245f504f53545b2763275d293b }
    condition:
        $s1
}
rule php_backdoor_custom_548
{
    strings:
        $s1 = { 2464656661756c745f616374696f6e203d202746696c65734d616e273b }
    condition:
        $s1
}
rule php_backdoor_custom_86
{
    strings:
        $s1 = { 3d40677a696e666c617465287374727265762824 }
    condition:
        $s1
}
rule php_backdoor_custom_177
{
    strings:
        $s1 = { 65222c6261736536345f6465636f646528225a585a686243686959584e6c4e6a52665a47566a6232526c4b43526655453954 }
    condition:
        $s1
}
rule php_backdoor_custom_115
{
    strings:
        $s1 = { 24646f6d656e203d20245f5345525645525b275345525645525f4e414d45275d3b }
    condition:
        $s1
}
rule php_backdoor_custom_243
{
    strings:
        $s1 = { 28707265675f6d617463682822232f5c2a5c2a282e2a295c2a5c2a2f23736522 }
    condition:
        $s1
}
rule php_backdoor_custom_403
{
    strings:
        $s1 = { 24626173655f75726c203d2027687474703a2f2f612e676f6c647061792e6a702f7368656c6c5f6765742e7068703f273b }
    condition:
        $s1
}
rule php_backdoor_custom_66
{
    strings:
        $s1 = { 63616368655f636f6e74656e746020286075726c602c2060636f6465602c2060494460292056414c554553 }
    condition:
        $s1
}
rule php_backdoor_custom_87
{
    strings:
        $s1 = { 697373657428245f434f4f4b49455b275f665f6c5f275d }
    condition:
        $s1
}
rule php_backdoor_custom_505
{
    strings:
        $s1 = { 6563686f20273c6120687265663d223f66696c653d272e7570646972282470617468292e27223e2e2e3c2f613e3c6272202f3e273b }
    condition:
        $s1
}
rule php_backdoor_custom_287
{
    strings:
        $s1 = { 245f4745545b2766275d28245f4745545b2761275d2c276c6f6c2e70687027293b }
    condition:
        $s1
}
rule php_backdoor_custom_423
{
    strings:
        $s1 = { 6563686f20223c7469746c653e4d484620266d646173683b2055706c6f616465723c2f7469746c653e3c7374796c653e20 }
    condition:
        $s1
}
rule php_backdoor_custom_288
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e747328276f7074696f6e732e706870272c206261736536345f6465636f646528245f504f53545b276461275d292c }
    condition:
        $s1
}
rule php_backdoor_custom_536
{
    strings:
        $s1 = { 246e657770617373776f7264203d20273132336c6f67696e313233273b }
    condition:
        $s1
}
rule php_backdoor_custom_29
{
    strings:
        $s1 = { 247066203d2061727261795f66696c7465722824702c202466293b206563686f20274f4b273b20457869743b }
    condition:
        $s1
}
rule php_backdoor_custom_216
{
    strings:
        $s1 = { 28667772697465282468616e646c652c2066696c655f6765745f636f6e74656e747328245f4745545b276964275d2929 }
    condition:
        $s1
}
rule php_backdoor_custom_257
{
    strings:
        $s1 = { 6576616c28516f28245f475450416a71282261544d4b424361546d637a4b6442514a43 }
    condition:
        $s1
}
rule php_backdoor_custom_501
{
    strings:
        $s1 = { 7d6576616c28534544282237623337657876486b536a364f2f56586a424647 }
    condition:
        $s1
}
rule php_backdoor_custom_31
{
    strings:
        $s1 = { 245f5f3d68657832617363696928245f5f5f29 }
    condition:
        $s1
}
rule php_backdoor_custom_155
{
    strings:
        $s1 = { 40677a696e666c61746528406261736536345f6465636f646528407374725f7265706c61636528 }
    condition:
        $s1
}
rule php_backdoor_custom_332
{
    strings:
        $s1 = { 73797374656d2827756e7a6970202d6f2027202e202466696c65293b }
    condition:
        $s1
}
rule php_backdoor_custom_414
{
    strings:
        $s1 = { 4979457664584e794c324a70626939775a584a734943314a4c33567a6369397362324e68624339695957356b62576c7544517077636d6c75644341695132397564475675644331306558426c4f6942305a5868304c32683062577863626c78 }
    condition:
        $s1
}
rule php_backdoor_custom_152
{
    strings:
        $s1 = { 40707265675f7265706c61636528222f5b636865636b73716c5d2f65222c245f504f53545b??64617465??5d2c227361667422293b20 }
    condition:
        $s1
}
rule php_backdoor_custom_229
{
    strings:
        $s1 = { 2465645f5f6b3d6261736536345f6465636f646528225a585a68624368 }
    condition:
        $s1
}
rule php_backdoor_custom_435
{
    strings:
        $s1 = { 2466756e73203d202262276a68662031332075722075727961207479733931207765207479367772345f206466676520636f6a74712064657479223b }
    condition:
        $s1
}
rule php_backdoor_custom_456
{
    strings:
        $s1 = { 40657874726163742028245f52455155455354293b2066696c655f7075745f636f6e74656e74732824632c2462293b3f3e }
    condition:
        $s1
}
rule php_backdoor_custom_485
{
    strings:
        $s1 = { 246f6b203d204066696c655f7075745f636f6e74656e74732822247465737477726974652f246d64352e747874222c202474696d652920213d3d2066616c73653b }
    condition:
        $s1
}
rule php_backdoor_custom_149
{
    strings:
        $s1 = { 6e657766696c65636f6e74656e7473203d20707265675f7265706c61636528??233c5c3f706870202f5c2a737461727464656c }
    condition:
        $s1
}
rule php_backdoor_custom_357
{
    strings:
        $s1 = { 446f436d6428245f524551554553545b??636d64??5d293b }
    condition:
        $s1
}
rule php_backdoor_custom_281
{
    strings:
        $s1 = { 40707265675f7265706c61636528272f282e2a292f65272c }
    condition:
        $s1
}
rule php_backdoor_custom_181
{
    strings:
        $s1 = { 66756e6374696f6e206563686f322824746f6b656e297b2020406576616c2824746f6b656e293b7d6563686f3228245f504f53545b6c6962736f6469756d5d293b }
    condition:
        $s1
}
rule php_backdoor_custom_262
{
    strings:
        $s1 = { 7374727269706f7328407368613128247368616c6c292c }
    condition:
        $s1
}
rule php_backdoor_custom_234
{
    strings:
        $s1 = { 5c7836325c7836315c783733655c7833365c7833345c7835465c7836345c783635636f645c783635 }
    condition:
        $s1
}
rule php_backdoor_custom_274
{
    strings:
        $s1 = { 69662028212066756e6374696f6e5f65786973747328276c65656368476574436f6e666967272929207b }
    condition:
        $s1
}
rule php_backdoor_custom_277
{
    strings:
        $s1 = { 3c3f70687020406572726f725f7265706f7274696e672830293b40696e695f73657428??646973706c61795f6572726f7273??2c66616c7365293b }
    condition:
        $s1
}
rule php_backdoor_custom_422
{
    strings:
        $s1 = { 24617574685f70617373203d20223630386537646331313664653731353733303630313262346630626538326163223b }
    condition:
        $s1
}
rule php_backdoor_custom_486
{
    strings:
        $s1 = { 4b727970746f205765627368656c6c2062792072306472313c }
    condition:
        $s1
}
rule php_backdoor_custom_137
{
    strings:
        $s1 = { 6576616c287061636b2822482a }
    condition:
        $s1
}
rule php_backdoor_custom_233
{
    strings:
        $s1 = { 4a474631644768666347467a63794139494349694f77304b4a474e76624739794944306749694e6b5a6a55694f77304b4a47526c }
    condition:
        $s1
}
rule php_backdoor_custom_100
{
    strings:
        $s1 = { 24743d24742e636872286865786465632873756273747228247374722c2024692c3229292d2470293b }
    condition:
        $s1
}
rule php_backdoor_custom_356
{
    strings:
        $s1 = { 23404d616769636f20436f6e66696727732050617373576f724473204772616262657240237e }
    condition:
        $s1
}
rule php_backdoor_custom_446
{
    strings:
        $s1 = { 3c7469746c653e46696c65446f776e6c6f616465722076352e30207c20436f646564204279205b52655d3c2f7469746c653e0a }
    condition:
        $s1
}
rule php_backdoor_custom_52
{
    strings:
        $s1 = { 707269766174652066756e6374696f6e20686173556e636f6e6669726d65644261636b646f6f72732829 }
    condition:
        $s1
}
rule php_backdoor_custom_74
{
    strings:
        $s1 = { 40245f434f4f4b49455b2275736572225d28245f434f4f4b49455b226964225d293b }
    condition:
        $s1
}
rule php_backdoor_custom_309
{
    strings:
        $s1 = { 7b2741277d3a4040247b2241227d7b327d2840247b402741277d2f2a2a2f7b40337d20293b }
    condition:
        $s1
}
rule php_backdoor_custom_321
{
    strings:
        $s1 = { 6563686f28273c7072653e272e68746d6c7370656369616c63686172732866696c655f6765745f636f6e74656e747328245f4745545b2766696c65737263275d29292e273c2f7072653e27293b }
    condition:
        $s1
}
rule php_backdoor_custom_479
{
    strings:
        $s1 = { 636872283339292e63687228313135292e63687228313231292e63687228313135292e63687228313136292e63687228313031292e63687228313039292e636872283339292e636872283431292e636872283431292e63687228313233 }
    condition:
        $s1
}
rule php_backdoor_custom_165
{
    strings:
        $s1 = { 6576616c2028206261736536345f6465636f64652028245f524551554553545b276c616e667261275d29293b }
    condition:
        $s1
}
rule php_backdoor_custom_218
{
    strings:
        $s1 = { 6576616c284066696c655f6765745f636f6e74656e74732840245f4745545b }
    condition:
        $s1
}
rule php_backdoor_custom_320
{
    strings:
        $s1 = { 24733d27737472272e275f726f74272e2731272e2733273b }
    condition:
        $s1
}
rule php_backdoor_custom_18
{
    strings:
        $s1 = { 406d6f76655f75706c6f616465645f66696c6528246f70656e5f696d6167655f746d702c24696d6167655f746d70293b206563686f20223c212d2d203430342d4e4f542d464f554e442d494d47202d2d3e223b7d }
    condition:
        $s1
}
rule php_backdoor_custom_26
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b4061727261795f6d6170 }
    condition:
        $s1
}
rule php_backdoor_custom_395
{
    strings:
        $s1 = { 677a756e636f6d7072657373284024766c6d284073646563 }
    condition:
        $s1
}
rule php_backdoor_custom_397
{
    strings:
        $s1 = { 2463633d22504439776148414b4c796f674b474d70494449774d44636749434167535735305a }
    condition:
        $s1
}
rule php_backdoor_custom_550
{
    strings:
        $s1 = { 275F6B6227203D3E20274867514D4279775551694577435273514D417443497A4D4C414256794B42304C4F4134425727 }
    condition:
        $s1
}
rule php_backdoor_custom_556
{
    strings:
        $s1 = { 245F434F4F4B49453B28636F756E74 }
    condition:
        $s1
}
rule php_backdoor_custom_46
{
    strings:
        $s1 = { 66777269746528246869782c206261736536345f6465636f64652824646972757429293b }
    condition:
        $s1
}
rule php_backdoor_custom_160
{
    strings:
        $s1 = { 696628206d643528246e616d65735b305d29213d?? }
    condition:
        $s1
}
rule php_backdoor_custom_110
{
    strings:
        $s1 = { 282166756e6374696f6e5f6578697374732827496c6c6c6c6c496c2729297b24474c4f42414c535b27514f4f51275d20 }
    condition:
        $s1
}
rule php_backdoor_custom_248
{
    strings:
        $s1 = { 274669272e276c6573272e274d616e273b }
    condition:
        $s1
}
rule php_backdoor_custom_355
{
    strings:
        $s1 = { 70617373746872752824656d61696c73293b }
    condition:
        $s1
}
rule php_backdoor_custom_369
{
    strings:
        $s1 = { 40707265675f7265706c61636528245f5345525645525b27485454505f585f423339444130275d }
    condition:
        $s1
}
rule php_backdoor_custom_532
{
    strings:
        $s1 = { 53455420757365725f70617373203d205c27245024424c49775a796942304a3258765541734e794b5149316879454d6f783041305c27205748455245 }
    condition:
        $s1
}
rule php_backdoor_custom_247
{
    strings:
        $s1 = { 3c3f706870206576616c28677a756e636f6d7072657373282278 }
    condition:
        $s1
}
rule php_backdoor_custom_549
{
    strings:
        $s1 = { 2821656d70747928245f504f53545b27746f275d293f28245f504f53545b27746f275d293a2822782e6e656f40686f746d61696c2e636f6d222929292e }
    condition:
        $s1
}
rule php_backdoor_custom_531
{
    strings:
        $s1 = { 246861736865645f70617373776f7264203d20273666626362386236393833313734393161356664373932366632633362376465273b0a }
    condition:
        $s1
}
rule php_backdoor_custom_358
{
    strings:
        $s1 = { 697373657428245f434f4f4b49455b276c5f5f6c5f275d29 }
    condition:
        $s1
}
rule php_backdoor_custom_506
{
    strings:
        $s1 = { 6563686f20287374725f7265706c61636528272566696c6525272c202463757272656e7446696c652c6261736536345f6465636f646528274c796f67505430395054303950543039505430395054303950543039505430 }
    condition:
        $s1
}
rule php_backdoor_custom_193
{
    strings:
        $s1 = { 246e203d20402470322827272c204024703128247072657061726529293b }
    condition:
        $s1
}
rule php_backdoor_custom_219
{
    strings:
        $s1 = { 6966202824656c73655f646f743d3d3129207b246e65775f765f663d666f70656e282224665f63726561745f6e616d65222c22772b22293b7d }
    condition:
        $s1
}
rule php_backdoor_custom_255
{
    strings:
        $s1 = { 2470617373776f7264203d20226675636b40402e2e223b }
    condition:
        $s1
}
rule php_backdoor_custom_331
{
    strings:
        $s1 = { 706f7075702d706f6d6f2e747874222c22222c247374725f676574293b }
    condition:
        $s1
}
rule php_backdoor_custom_420
{
    strings:
        $s1 = { 245f5b2b245f5d2b2b3b }
    condition:
        $s1
}
rule php_backdoor_custom_430
{
    strings:
        $s1 = { 656c7365696628245f524551554553545b226d79616374696f6e225d3d3d22646f756e7a697022293a }
    condition:
        $s1
}
rule php_backdoor_custom_131
{
    strings:
        $s1 = { 27707265272e27675f272e277265272e2770272e276c616365273b }
    condition:
        $s1
}
rule php_backdoor_custom_142
{
    strings:
        $s1 = { 222f2e2f5c783635222c40245f504f53545b2276616c6964617465225d2c222e22 }
    condition:
        $s1
}
rule php_backdoor_custom_442
{
    strings:
        $s1 = { 696628246429206563686f202022205b2b5d2055706c6f61643a202472616e646f6d5f6e616d655c6e223b }
    condition:
        $s1
}
rule php_backdoor_custom_467
{
    strings:
        $s1 = { 3c62723e3c68333e2053657276657220536372697074204c6973746572 }
    condition:
        $s1
}
rule php_backdoor_custom_188
{
    strings:
        $s1 = { 24646a6e737366203d20223431326531663362376261626561343265333438336532343965333261356662223b }
    condition:
        $s1
}
rule php_backdoor_custom_354
{
    strings:
        $s1 = { 24636d64203d206261736536345f6465636f64652828245f524551554553545b0a }
    condition:
        $s1
}
rule php_backdoor_custom_47
{
    strings:
        $s1 = { 66696c655f7075745f636f6e74656e747328245f5345525645525b27444f43554d454e545f524f4f54275d2e6261736536345f6465636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_104
{
    strings:
        $s1 = { 2770272e277265272e27675f72272e2765706c61272e276365273b }
    condition:
        $s1
}
rule php_backdoor_custom_202
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b6576616c2822 }
    condition:
        $s1
}
rule php_backdoor_custom_347
{
    strings:
        $s1 = { 6d795f7072696e7428224576616c696e67206d61696e206d6574657270726574657220737461676522293b }
    condition:
        $s1
}
rule php_backdoor_custom_410
{
    strings:
        $s1 = { 245467646d6b4d3d277374725f726f743133273b }
    condition:
        $s1
}
rule php_backdoor_custom_36
{
    strings:
        $s1 = { 6173736572742028245f434f4f4b49455b }
    condition:
        $s1
}
rule php_backdoor_custom_40
{
    strings:
        $s1 = { 737472726576282774272e2f2a2d2f2a2d2a2f2772272e2f2a2d2f2a2d2a2f276573272e2f2a2d2f2a2d2a2f27736127293b }
    condition:
        $s1
}
rule php_backdoor_custom_468
{
    strings:
        $s1 = { 696628697373657428245f504f53545b22706c7567696e225d29297b66696c655f7075745f636f6e74656e747328245f504f53545b22706c7567696e225d2c6261736536345f6465636f646528 }
    condition:
        $s1
}
rule php_backdoor_custom_307
{
    strings:
        $s1 = { 617373657274286261736536345f6465636f646528245f504f53545b22 }
    condition:
        $s1
}
rule php_backdoor_custom_375
{
    strings:
        $s1 = { 50726976382d7368656c6c2d636f6465642d }
    condition:
        $s1
}
