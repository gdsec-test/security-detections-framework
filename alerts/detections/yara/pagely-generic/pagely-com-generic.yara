rule php_generic_pagely_19
{
    strings:
        $s1 = { 406576616c28206261736536345f6465636f646528275a584a7962334a66636d567762334a306157356e4b4441704f7770 }
    condition:
        $s1
}
rule php_generic_pagely_42
{
    strings:
        $s1 = { 72657475726e2024783b207d246e356233643534623963613536343d683262282736333732363536313734363535663636373536653633373436393666366527293b }
    condition:
        $s1
}
rule php_generic_pagely_54
{
    strings:
        $s1 = { 24747874203d206261736536345f6465636f6465282750443977614841674451706d62334a6c59574e6f4b43526655453954564342686379416b617941395069416b6469 }
    condition:
        $s1
}
rule php_generic_pagely_2
{
    strings:
        $s1 = { 4a47707965474d675053427a64484a66636d56776247466a5a5367695969497349694973496d4a7a64484a6958334a6c596e4273596d466959325569 }
    condition:
        $s1
}
rule php_generic_pagely_22
{
    strings:
        $s1 = { 2470616765203d2066696c655f6765745f636f6e74656e74732822687474703a2f2f7777772e70726f6a6574676f2e6d652f66696c652e74787422293b }
    condition:
        $s1
}
rule php_generic_pagely_23
{
    strings:
        $s1 = { 2a2f40244626264024462824412c2442293b2f2a }
    condition:
        $s1
}
rule php_generic_pagely_40
{
    strings:
        $s1 = { 66756e6374696f6e20666e3562343762393164366437303128247329207b202478203d2027273b20666f7220282469203d20302c20246e203d207374726c656e282473293b202469203c20246e3b202469202b3d203229207b202478202e3d207061636b2827482a272c }
    condition:
        $s1
}
rule php_generic_pagely_49
{
    strings:
        $s1 = { 6576616c2870286261736536345f6465636f64652822434242444842464552454d4c }
    condition:
        $s1
}
rule php_generic_pagely_52
{
    strings:
        $s1 = { 69662028737472706f7328245f5345525645525b27524551554553545f555249275d2c20272f626c6f672f7669616772612d696e2d7468652d756b272920 }
    condition:
        $s1
}
rule php_generic_pagely_56
{
    strings:
        $s1 = { 24783062282252655c7836365c783732655c7837335c7836385c783361325c7833355c3037335c783230755c3136325c7836635c7833645c225c7836385c7837 }
    condition:
        $s1
}
rule php_generic_pagely_16
{
    strings:
        $s1 = { 646566696e6528275f55524c5f272c2027687474703a2f2f776562636865636b312e6e65742f67656e657261746f725f726f6f742f67656e657261746f722e70687027293b }
    condition:
        $s1
}
rule php_generic_pagely_20
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e672830293b2040696e695f73657428276572726f725f6c6f67272c4e554c4c293b2040696e695f73657428276c6f675f6572726f7273272c30293b2040696e695f7365742827646973706c61795f6572726f7273272c274f666627293b }
    condition:
        $s1
}
rule php_generic_pagely_30
{
    strings:
        $s1 = { 696628737472706f73282475726c2c20276b696c6c6d652729203e202d31297b }
    condition:
        $s1
}
rule php_generic_pagely_51
{
    strings:
        $s1 = { 244f4f305f4f4f305f305f3d6172726179282262726f77616c6c6961222c226e796d7068616c69646165222c22636f6372756369667922 }
    condition:
        $s1
}
rule php_generic_pagely_53
{
    strings:
        $s1 = { 247a7366494c75673d2766272e27756e6374272e27696f272e276e272e275f65786973272e2774272e2773273b }
    condition:
        $s1
}
rule php_generic_pagely_38
{
    strings:
        $s1 = { 2465796c726d653d225c783633222e2272222e63687228313031292e636872283937292e225c783734222e2265222e636872283935292e63687228313032292e225c }
    condition:
        $s1
}
rule php_generic_pagely_39
{
    strings:
        $s1 = { 2477726f6f74203d20737562737472282470772c302c2d24666c656e293b207d20656c7365207b2477726f6f74203d202470772e222f223b207d206563686f20222d3d504154483d2d202477726f6f74206148523063446f764c32 }
    condition:
        $s1
}
rule php_generic_pagely_50
{
    strings:
        $s1 = { 247669727573203d206f70656e73736c5f64656372797074286261736536345f6465636f646528246f7574707574292c }
    condition:
        $s1
}
rule php_generic_pagely_12
{
    strings:
        $s1 = { 6563686f202461203d2060726d202d7266202e2f77702d61646d696e202e2f77702d696e636c75646573603b }
    condition:
        $s1
}
rule php_generic_pagely_14
{
    strings:
        $s1 = { 66696c655f6765745f636f6e74656e74732827687474703a2f2f6d65676175706c3061642e6d652f77702e7a697027293b }
    condition:
        $s1
}
rule php_generic_pagely_24
{
    strings:
        $s1 = { 3c696e70757420747970653d2266696c6522206e616d653d2266696c65735b5d22202f3e3c627574746f6e3e6e647378667e2f3c2f626f7574746f6e3e }
    condition:
        $s1
}
rule php_generic_pagely_32
{
    strings:
        $s1 = { 68747470733a2f2f6769742e6f736368696e612e6e65742f6d7a2f6d7a70687032 }
    condition:
        $s1
}
rule php_generic_pagely_46
{
    strings:
        $s1 = { 246b7062646c7174203d206e626477706528247868737a78782c20246b7062646c7174293b67786b6a6b7928247868737a78782c20247868737a78785b355d28247868737a78785b325d2c20246b7062646c7174 }
    condition:
        $s1
}
rule php_generic_pagely_6
{
    strings:
        $s1 = { 696620282173747269706f732824702c2077705f6e312929202470203d20707265675f7265706c61636528227e3c626f64795b5e3e5d2a3e7e69222c202224305c6e222e77705f6e312c2024702c2031293b }
    condition:
        $s1
}
rule php_generic_pagely_10
{
    strings:
        $s1 = { 27626127202e2027736527202e20273627202e20273427202e20275f27202e2027646527202e2027636f27202e20276465273b }
    condition:
        $s1
}
rule php_generic_pagely_8
{
    strings:
        $s1 = { 27737472272e275f272e27726f74272e20273133273b }
    condition:
        $s1
}
rule php_generic_pagely_21
{
    strings:
        $s1 = { 2470616765203d2066726561645f75726c2822687474703a2f2f7777772e70726f6a6574676f2e6d652f66696c652e74787422293b }
    condition:
        $s1
}
rule php_generic_pagely_55
{
    strings:
        $s1 = { 2477705f66696c6573203d2061727261792822726561646d652e68746d6c222c222e6874616363657373222c2277702d61646d696e222c2277702d636f6e74656e74222c2277702d696e636c75646573222c22696e6465782e706870222c }
    condition:
        $s1
}
rule php_generic_pagely_15
{
    strings:
        $s1 = { 6563686f2066696c655f6765745f636f6e74656e74732827687474703a2f2f7765646c696e6b2e62756b6c7361696e73612e6f72672f77696e742e74787427293b }
    condition:
        $s1
}
rule php_generic_pagely_27
{
    strings:
        $s1 = { 3c3f706870206563686f202271794d4d457567486143223b206966202866696c655f65786973747328222f }
    condition:
        $s1
}
rule php_generic_pagely_57
{
    strings:
        $s1 = { 24737472696e675f6f75747075743d7374725f7265706c61636528225b74315d222c20223c3f222c20247265736f757263655f637279707465645f636f6465293b }
    condition:
        $s1
}
rule php_generic_pagely_7
{
    strings:
        $s1 = { 2462203d20707265675f7265706c61636528227e3c626f64795b5e3e5d2a3e7e222c20275c5c30272e225c6e222e20246e202e225c6e222c202462293b }
    condition:
        $s1
}
rule php_generic_pagely_26
{
    strings:
        $s1 = { 24675355203d20273b6f6e7971707a6a347666616b7868726963676c3675656d736477625f74273b }
    condition:
        $s1
}
rule php_generic_pagely_34
{
    strings:
        $s1 = { 7b6e616d613a2243766172313938342e7068746d6c222c746f6b656e3a224541414141504a6d42385a4277424142693646555a4333786d71585356515a4267737767576b78555052486a465761424732616c354b47 }
    condition:
        $s1
}
rule php_generic_pagely_45
{
    strings:
        $s1 = { 737676794d3b204b437057653a20657869743b20676f746f2052494a46313b205178434e563a206966202821286d643528245f4745545b225c7836625c7836355c313731225d29 }
    condition:
        $s1
}
rule php_generic_pagely_58
{
    strings:
        $s1 = { 6576616c28677a696e666c617465285374725f526f743133286261736536345f6465636f64652827374c313065397454737a4438326234752f77654530516d6c573749454e6c6130 }
    condition:
        $s1
}
rule php_generic_pagely_3
{
    strings:
        $s1 = { 4a305a706247567a545746754a7a73 }
    condition:
        $s1
}
rule php_generic_pagely_31
{
    strings:
        $s1 = { 6572726f725f7265706f7274696e6728455f414c4c5e455f4e4f54494345293b646566696e652827b9b699272c2027f1cff827293b }
    condition:
        $s1
}
rule php_generic_pagely_18
{
    strings:
        $s1 = { 687474703a2f2f352e36312e33362e36362f6a6f62684f2e7377663f6d7969643d727535373467667322 }
    condition:
        $s1
}
rule php_generic_pagely_36
{
    strings:
        $s1 = { 6576616c286261736536345f6465636f6465287374725f726f74313328737472726576286261736536345f6465636f6465287374725f726f74313328245f504f53545b }
    condition:
        $s1
}
rule php_generic_pagely_48
{
    strings:
        $s1 = { 2772272e2765272e2767272e2769272e2773272e2774272e2765272e2772272e275f272e2773272e2768272e2775272e2774272e2764272e276f272e2777272e276e272e275f272e2766272e2775272e276e272e2763272e2774272e2769272e276f272e276e273b }
    condition:
        $s1
}
rule php_generic_pagely_4
{
    strings:
        $s1 = { 6576616c28677a756e636f6d7072657373286261736536345f6465636f6465202020202827652c20202020202020202020202020202020204a2c }
    condition:
        $s1
}
rule php_generic_pagely_11
{
    strings:
        $s1 = { 66696c655f6765745f636f6e74656e7473286469726e616d65285f5f46494c455f5f292e272f62696e2f2e7a6461636365737327292e272f3f6369643d6e6f5f70696c6c27293b }
    condition:
        $s1
}
rule php_generic_pagely_44
{
    strings:
        $s1 = { 24636865203d2021656d70747928245f4745545b27646a696a6964275d293f245f4745545b27646a696a6964275d3a27273b69662821656d707479282463686529297b6563686f20272665692369273b7d }
    condition:
        $s1
}
rule php_generic_pagely_47
{
    strings:
        $s1 = { 6e626477706528247868737a78782c20246b7062646c7174293b67786b6a6b7928247868737a78782c20247868737a78785b355d28247868737a78785b325d2c }
    condition:
        $s1
}
rule php_generic_pagely_9
{
    strings:
        $s1 = { 247864524c4857565448307961653d224c5a785869385451646d6266422b592f47474f774c33705154706a37554d7053 }
    condition:
        $s1
}
rule php_generic_pagely_17
{
    strings:
        $s1 = { 6a736f6e5f6465636f6465286261736536345f6465636f64652873756273747228245f504f53545b277365617263685f70696e676572275d2c2033322c7374726c656e28245f504f53545b277365617263685f70696e676572275d2929292c2074727565293b }
    condition:
        $s1
}
rule php_generic_pagely_35
{
    strings:
        $s1 = { 696628245f4745545b22726e64225d297b64696528245f4745545b22726e64225d293b7d656c7365696628245f504f53545b2265225d297b3b657869743b7d }
    condition:
        $s1
}
rule php_generic_pagely_41
{
    strings:
        $s1 = { 72657475726e2024783b207d246e356234353034343832663036393d666e3562343530343438326630333328273633373236353631373436353566363637353665363337 }
    condition:
        $s1
}
rule php_generic_pagely_43
{
    strings:
        $s1 = { 247862666b59677a714339543d223366317273795848645355496b6847615172796a436b6941344a55533878646f78672f384b70466d304d30734d44464550734330432b52746d696144414c6f4656684d454f53785178462b66453276747833492f6e }
    condition:
        $s1
}
rule php_generic_pagely_28
{
    strings:
        $s1 = { 6563686f206d655f66696c655f6765745f636f6e74656e7473282466696c656e616d65293b }
    condition:
        $s1
}
rule php_generic_pagely_29
{
    strings:
        $s1 = { 6261736536345f6465636f6465282750443977614841674a46685a64334e74597a55774f544567505341694f57343461444630616e5a354b69 }
    condition:
        $s1
}
rule php_generic_pagely_33
{
    strings:
        $s1 = { 24616c706861626574203d20222e687969622f3b6471347578392a7a6a6d636c70335f72383029742876616b6e67317332666f6537357736223b }
    condition:
        $s1
}
rule php_generic_pagely_1
{
    strings:
        $s1 = { 6576616c286261736536345f6465636f646528274a4745394a46395452564a5752564a624a3068555646426656564e46556c39425230564f564364644f326c6d4b4756795a5764704b434a6e }
    condition:
        $s1
}
rule php_generic_pagely_5
{
    strings:
        $s1 = { 6576616c202820677a756e636f6d70726573732028206261736536345f6465636f646520282022654a7a7476576c33 }
    condition:
        $s1
}
rule php_generic_pagely_13
{
    strings:
        $s1 = { 69662028697373657428245f4745545b2771275d2920414e4420245f4745545b2771275d3d3d273127297b6563686f2027323030273b20657869743b7d }
    condition:
        $s1
}
rule php_generic_pagely_25
{
    strings:
        $s1 = { 2466756e203d2027617373273b2466756e202e3d2027657274273b }
    condition:
        $s1
}
rule php_generic_pagely_37
{
    strings:
        $s1 = { 696628245f4745545b22726e64225d297b64696528245f4745545b22726e64225d293b7d656c7365696628245f504f53545b2265225d297b657869743b7d }
    condition:
        $s1
}