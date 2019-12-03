node.default['packer']['url_base'] = 'https://releases.hashicorp.com/packer'
node.default['packer']['version'] = '1.4.5'
node.default['packer'][node.default['packer']['version']]['prefix'] = ''
node.default['packer']['arch'] = node['kernel']['machine'] =~ /x86_64/ ? "amd64" : "386"

# Transform raw output of the bintray checksum list into a Hash[filename, checksum].
# https://dl.bintray.com/mitchellh/packer/${VERSION}_SHA256SUMS?direct

node.default['packer']['0.5.1']['raw_checksums'] = <<-EOF
    a0d8db4944d0024af05e256357cad014662eddefef67b1b2fe8a5060659a5be2  0.5.1_darwin_386.zip
    56bec31f0d3540d566ef86979b25367660d7e72c010c9d87ef91c5c2138e9eae  0.5.1_darwin_amd64.zip
    337651f4dd4f897413eb07e8d2cd821a0246d04c4235ce398af58f7939e097e1  0.5.1_freebsd_386.zip
    ae356b68517aa75d08736c44d838b6bd4a19203315ee8afffff5de35684e1464  0.5.1_freebsd_amd64.zip
    bbd2468d69195b4227034aa07474e87c2bcfe2250ae620085219e870e6b33bf6  0.5.1_freebsd_arm.zip
    cc7741165a3d5f66c1d4af3ea3b1e80ebe03cb2ce5e0ff27ff43ecac64f1dc7a  0.5.1_linux_386.zip
    fa68149f4356ad48a6393dbf9e81839a40aad115e5bad83833ff9ccf6a0239b8  0.5.1_linux_amd64.zip
    6a6b724df3bc51478cc1cd4ccbc000924bbe9018a4ded74d3b6e0409cb9092e0  0.5.1_linux_arm.zip
    a2ff5410a871baafef2ffd1924f5b6d7fe1ba443ba0b23071e2c928935d173e6  0.5.1_openbsd_386.zip
    41c1edd5faf9041081f1dbaa6eb14e9f18cdb25a8dab85f33c08701bd0275817  0.5.1_openbsd_amd64.zip
    350480400d31c00e1604fce8744b5f3d279c15cf8c49cd7b59e1412e316dae01  0.5.1_windows_386.zip
    6c5c43aa92f41f23199b9142f08950e57e400e3fed9196132a111f65b499c214  0.5.1_windows_amd64.zip
EOF

node.default['packer']['0.5.1']['raw_checksums'] = <<-EOF
    a0d8db4944d0024af05e256357cad014662eddefef67b1b2fe8a5060659a5be2  0.5.1_darwin_386.zip
    56bec31f0d3540d566ef86979b25367660d7e72c010c9d87ef91c5c2138e9eae  0.5.1_darwin_amd64.zip
    337651f4dd4f897413eb07e8d2cd821a0246d04c4235ce398af58f7939e097e1  0.5.1_freebsd_386.zip
    ae356b68517aa75d08736c44d838b6bd4a19203315ee8afffff5de35684e1464  0.5.1_freebsd_amd64.zip
    bbd2468d69195b4227034aa07474e87c2bcfe2250ae620085219e870e6b33bf6  0.5.1_freebsd_arm.zip
    cc7741165a3d5f66c1d4af3ea3b1e80ebe03cb2ce5e0ff27ff43ecac64f1dc7a  0.5.1_linux_386.zip
    fa68149f4356ad48a6393dbf9e81839a40aad115e5bad83833ff9ccf6a0239b8  0.5.1_linux_amd64.zip
    6a6b724df3bc51478cc1cd4ccbc000924bbe9018a4ded74d3b6e0409cb9092e0  0.5.1_linux_arm.zip
    a2ff5410a871baafef2ffd1924f5b6d7fe1ba443ba0b23071e2c928935d173e6  0.5.1_openbsd_386.zip
    41c1edd5faf9041081f1dbaa6eb14e9f18cdb25a8dab85f33c08701bd0275817  0.5.1_openbsd_amd64.zip
    350480400d31c00e1604fce8744b5f3d279c15cf8c49cd7b59e1412e316dae01  0.5.1_windows_386.zip
    6c5c43aa92f41f23199b9142f08950e57e400e3fed9196132a111f65b499c214  0.5.1_windows_amd64.zip
EOF

node.default['packer']['0.6.1']['prefix'] = ""
node.default['packer']['0.6.1']['raw_checksums'] = <<-EOF
    f941d12e5db1dc49665a9b62299df9f97b9dcb4b5dbabbbdf77211e46935aea5  0.6.1_darwin_386.zip
    1ab1cf76be8ab1b953f0e634c96f8a09a9d17eb3d180b120b9d19afff2a94cb4  0.6.1_darwin_amd64.zip
    b1b1d4e34494cbc3da5f3770770201b96426f79db196f415bcfefe0c53ef6ace  0.6.1_freebsd_386.zip
    21ea9231623f156ff1600d60ea024c688a8c526f4cfb62e070e2f158153391e6  0.6.1_freebsd_amd64.zip
    341d9790aa4183085fdea4f5e1998160a3cfbce390a46bc02259d1cfcf95df40  0.6.1_freebsd_arm.zip
    8b83a1c4585335699a675f2bafa004e6da7f46394cd18b1b0218ca9105d4e64f  0.6.1_linux_386.zip
    9c13a55ab7db13509c8556f5d416ef373641da072f54686e7689c18a25b85aea  0.6.1_linux_amd64.zip
    1782d7c3fbbf9376e8fcd22f47247d8a6e9a4099599d4d8c3a8160346c0ee04b  0.6.1_linux_arm.zip
    c32954282f3a249682b0322f89b9a0919793fc445bc7f8d53ad816d46b057b00  0.6.1_openbsd_386.zip
    0d468b1f3244394b2615f78a1a47f61c77110465fa5c270899f32e6387a680e8  0.6.1_openbsd_amd64.zip
    b50e11e0f37efa94de0eeb4d10e1add050d4bee87773dea60faab15da38122f8  0.6.1_windows_386.zip
    1083c4232d6a3a50858b31e99e7e963c799ca9c6c5dd9f0621472c1cb9a33821  0.6.1_windows_amd64.zip
EOF


node.default['packer']['0.7.5']['prefix'] = "packer_"
node.default['packer']['0.7.5']['raw_checksums'] = <<-EOF
    72d57fe6a6ec2660dda2aed73198a4c4d9152037831d6aa44c64a28307c299c7  packer_0.7.5_darwin_386.zip
    c0e149c4515fe548c1daeafabec3b4a091f2aa0c6936723382b3f6fe5a617880  packer_0.7.5_darwin_amd64.zip
    6bce28c51a1862cbc3071421546620fb27007732f7a8470054e7267ca3521b95  packer_0.7.5_freebsd_386.zip
    508293b60f525c44560ca569db5b63b6f92294f655c61b076243a98a0ea75604  packer_0.7.5_freebsd_amd64.zip
    1cef5f1875a19b9c46daca5f36739bf2e9c9d68b1f27319abdc36c02837ac662  packer_0.7.5_freebsd_arm.zip
    6a6ee79d51909f04f734c15a0e12ebcaba3f2cf4d449906f6a186490774262f9  packer_0.7.5_linux_386.zip
    8fab291c8cc988bd0004195677924ab6846aee5800b6c8696d71d33456701ef6  packer_0.7.5_linux_amd64.zip
    8a7d63f0a9282f7b0a833a8455d37f5916d5a9200c17c83627922e08ed9ec2ca  packer_0.7.5_linux_arm.zip
    986d3b038f54ef86de313b10d45248c78159ebf5850615ab326d6e57229086a6  packer_0.7.5_openbsd_386.zip
    c11a67715de000de6742ebe7fb7187ba1db08333ec3941111a72672f0eb27509  packer_0.7.5_openbsd_amd64.zip
    99b879f491df08fa217193edea0b777341c73d4a145f2329b5c795d821258536  packer_0.7.5_windows_386.zip
    1dccdb825bbdd3487747771f58cecb5cbd0a73d44b52958f0d09ac9086b861b9  packer_0.7.5_windows_amd64.zip
EOF

node.default['packer']['0.8.6']['prefix'] = "packer_"
node.default['packer']['0.8.6']['raw_checksums'] = <<-EOF
    1fb3b1382885f39c1f1f159fc7a6ef4be12d074c97fba76e0050d1990a990aed  packer_0.8.6_darwin_386.zip
    91b5e5d4524a7a2f09a07aad1c8e26e1200b47191a42c1b2facac4a27fd674d0  packer_0.8.6_darwin_amd64.zip
    c1eee9159a2b808a98392026b18b9b8d273dc7315729be223b872f244ee4a8a2  packer_0.8.6_freebsd_386.zip
    bd0dac59e22a490068f45e4d97a8e698637efca88c89caa7df764ea96bd7b718  packer_0.8.6_freebsd_amd64.zip
    4ca3827f70af25656dd3eff6ac442b0e62adc28d6ea1d56f47721189bb7d0453  packer_0.8.6_freebsd_arm.zip
    d1385af26ea42560ddc4f4958c88cb00c3e4a9f8a2d88a81c96b4bf1cb60369b  packer_0.8.6_linux_386.zip
    2f1ca794e51de831ace30792ab0886aca516bf6b407f6027e816ba7ca79703b5  packer_0.8.6_linux_amd64.zip
    958cbae3f99990946c1de9af238bf1760c3382f83c4975a32be54cfb0378d8d8  packer_0.8.6_linux_arm.zip
    009f30cf9f137429ca4dc2c175e0431a72f44ba3dd427cb8a173c68c7d3be7eb  packer_0.8.6_openbsd_386.zip
    bfab2f16a6b4f34e317d792ad97c3e879304dc8ae7866e70737f61ebfc8952a0  packer_0.8.6_openbsd_amd64.zip
    8d0bd037909206926d988b30e9336faf105dffe97c2924d455b28de437557c7f  packer_0.8.6_windows_386.zip
    786503f2ffe658c1b318af227eabb8c10f3f425608ad4ef709206757931b7eee  packer_0.8.6_windows_amd64.zip
EOF

node.default['packer']['0.10.1']['prefix'] = "packer_"
node.default['packer']['0.10.1']['raw_checksums'] = <<-EOF
    7974c24313230dfe6a13a81332c3a2f5119d4c589ca3b7ead6decf4895486c71  packer_0.10.1_darwin_386.zip
    fac621bf1fb43f0cbbe52481c8dfda2948895ad52e022e46f00bc75c07a4f181  packer_0.10.1_darwin_amd64.zip
    951012ddd2564cfe1cf901b8486a36896f89d4c4e75b3ed85d6f9b49c06ac14e  packer_0.10.1_freebsd_386.zip
    170459ee7a1b2360f49a07ecffbadffe5407826f9514af10a25c3f19e1721e43  packer_0.10.1_freebsd_amd64.zip
    3360dad292c16d2893f6138edd33d6f8eba00f1985330ad797f80670b3032e2e  packer_0.10.1_freebsd_arm.zip
    9146b94115684a9725b2c1b5e5fbc412f30caaca136dbad4028423d6d6d3b6e4  packer_0.10.1_linux_386.zip
    7d51fc5db19d02bbf32278a8116830fae33a3f9bd4440a58d23ad7c863e92e28  packer_0.10.1_linux_amd64.zip
    1e110fb8ade48f959e426cf07603240fdc050d19ee8097e824459bf5e0638461  packer_0.10.1_linux_arm.zip
    b5a25296056ac6511a370e7357b3723de313bfc8ffcb8bd850d6ba8d77b8493e  packer_0.10.1_openbsd_386.zip
    255251a5dd93bba3c286b22b95ee9df63a1270c5c57c355263d0bebf692513da  packer_0.10.1_openbsd_amd64.zip
    9c3c3483a8b6dd6d116747bfcccbf6f530ffab9bb46b47d9a49bdcb92c145914  packer_0.10.1_windows_386.zip
    623013056dc662f29817dce6bd31e6fb669883a35ea9311951bbcea4eb9c59f7  packer_0.10.1_windows_amd64.zip
EOF

node.default['packer']['0.11.0']['prefix'] = "packer_"
node.default['packer']['0.11.0']['raw_checksums'] = <<-EOF
    4b6348bfdd8d086c20d919e0abde83fe0d0d1758c25463075f1fad42c5ac0efa  packer_0.11.0_darwin_386.zip
    5e3c3448f0efc33069ecfeae698eea475b37ebff385db596f6f4621edfd52797  packer_0.11.0_darwin_amd64.zip
    2fd05aaa9f70248a783df8aa6ef38457a006b389c5e2111167123ee4dd0b1bd5  packer_0.11.0_darwin_arm.zip
    f355cf0145bccdd6e4dc7d8c4b2470e4c8887719ab0fbc4f6edb96db4246a0a0  packer_0.11.0_freebsd_386.zip
    e2c5776e90e1bb3f4f3846090ec1b9285e37da226ce7c7351792af046d06ff79  packer_0.11.0_freebsd_amd64.zip
    176fea5a1ab4589ca727d4f54dc1b0cd7c7e1c98172adb22540fea4d85af603e  packer_0.11.0_freebsd_arm.zip
    abc25443416641e2277c8d968c6557bf9a009f9dc6ece4f0932acbb53c6c6fee  packer_0.11.0_linux_386.zip
    318ffffa13763eb6f29f28f572656356dc3dbf8d54c01ffddd1c5e2f08593adb  packer_0.11.0_linux_amd64.zip
    bf6fcfe99f6e35cf179d42af01d69bb10ee33ae2a824cbdfc71aba52f3b92a93  packer_0.11.0_linux_arm.zip
    d4ba32f50f02f1cdd17d67d41f0f873670c3f3f46f905ff1d376e45defff6a9a  packer_0.11.0_openbsd_386.zip
    a95fdc04df3f9fc5dea49943d6cd7830e0281c7c9ce8e4f1715ee04b6c7363bb  packer_0.11.0_openbsd_amd64.zip
    ff8149f71021ee65e16c264e42423082b079733a612eb2b6a0a959abd2160d4c  packer_0.11.0_windows_386.zip
    0a5fae47bd7269a3e739e7f9e6b6dea7564a80e02f30a152c9a071155eaaa65d  packer_0.11.0_windows_amd64.zip
EOF

node.default['packer']['0.12.0']['prefix'] = "packer_"
node.default['packer']['0.12.0']['raw_checksums'] = <<-EOF
    9fe5561a2be482989dd518d7e9616c2dcfe5111e749489ceadde5bbdf9e6b1b8  packer_0.12.0_darwin_386.zip
    e3f25ad619f35e10a4195c971d78f29abceb16877bbf2bd75182140373d02bd3  packer_0.12.0_darwin_amd64.zip
    f5cf377c17c2513622034d2e602d820f5fed31d807edf2c424f4891612579d0c  packer_0.12.0_darwin_arm.zip
    58bd298378fe811f2fdb0eb71f8d509dc58f997da32c135a04574133b05ee009  packer_0.12.0_freebsd_386.zip
    6b8a587e7f2a4a0dd26a7d523e474b0b30259b9683f2677cecec837eeab5ff0b  packer_0.12.0_freebsd_amd64.zip
    5a2a90741725993751ca5da9dbf29898f2196d005852dc1da72985d3c48be77f  packer_0.12.0_freebsd_arm.zip
    1b63006e1799f530755910d48b0858d80f3e6300b245511f1bc8a082108b92b3  packer_0.12.0_linux_386.zip
    ce6362d527ba697e40b8c90a98d2034b7749e2357fa238b08536aed44f037073  packer_0.12.0_linux_amd64.zip
    cd6482ad0b3c80d386989e73a7927248558fb627b53bbfd2f490d7a473a81d17  packer_0.12.0_linux_arm.zip
    99fb287ce60ddd27bcdda11c87cceab3fcfc6921290bb2ee279bf3646df2f23f  packer_0.12.0_openbsd_386.zip
    8a48bb7865b22a219c6d0085e20d170cb0f852580732bf45016da43be4fd8131  packer_0.12.0_openbsd_amd64.zip
    1b346c6f381e21e92a589dfcc0eafc7c2b87f10cdfc524e3c7128dd0a64a9763  packer_0.12.0_windows_386.zip
    4d1f9733b3cafc9e0ab2b1e9957dc2621a57f209a78d51ac5f5312cbcbb4e300  packer_0.12.0_windows_amd64.zip
EOF

node.default['packer']['1.0.4']['prefix'] = "packer_"
node.default['packer']['1.0.4']['raw_checksums'] = <<-EOF
    39ffdb34ad57b639eac99c943dd84cdc2676195bd52cc9c3cc72d2485840c0c7  packer_0.12.0_darwin_386.zip
    a7aef181b9f6371cd8d9c18dc110cd28684eb1095665ba4c9c28786d79d10f17  packer_0.12.0_darwin_amd64.zip
    27c090bef906b6b98bc080d6acd6764626a7d640c1c895f085d67f08e83e74bd  packer_0.12.0_freebsd_386.zip
    8c6aebcaf228d6883cd6afda4b88028cd8168fd04d92feb016b7b4a79571d0a2  packer_0.12.0_freebsd_amd64.zip
    fb7ae008f05950a895e33c724722bb408a45918d0d5649c86a5631b087f3af17  packer_0.12.0_freebsd_arm.zip
    b7f541c4a3b217cd0e38c3a13405cd3dcd29e3bd2d38fb8e20ae54b4b38a1014  packer_0.12.0_linux_386.zip
    646da085cbcb8c666474d500a44d933df533cf4f1ff286193d67b51372c3c59e  packer_0.12.0_linux_amd64.zip
    c35913e0fb48fcf28011a4268ff179812d84243088d7bb0931727cb54ee668a9  packer_0.12.0_linux_arm.zip
    e19208bddc9da8844eaff96c49d7cb8269d5e43a546cee721683faf4b88641f0  packer_0.12.0_openbsd_386.zip
    487ca4f29c327b389370768cb303ade4d791854918d52632be305ac9e614e64f  packer_0.12.0_openbsd_amd64.zip
    8e05658de4ba4170530b5e73f6f241a8652a685517797c4323ea6e0b65a4f37c  packer_0.12.0_windows_386.zip
    1a2ae283a71810a307299c05df73e96890fb7503f1b32c52850356ddb750d877  packer_0.12.0_windows_amd64.zip
EOF

node.default['packer']['1.4.1']['prefix'] = "packer_"
node.default['packer']['1.4.1']['raw_checksums'] = <<-EOF
    0dea781045103178ffd8a469c5e0b0f7b91561d0643d849969e37e8801d304a9  packer_1.4.1_darwin_386.zip
    2c5d4a2d0bf9e02dc790fddaa0a74e8fedb6ddd74c6f3b85d04536d9d757fe07  packer_1.4.1_darwin_amd64.zip
    ce8f1ccde4e132b74217bf4dd98a828254196d244eadd892b76bb745f52c36b8  packer_1.4.1_freebsd_386.zip
    419632e9af87e26efc6d5ff8d30fe442c106bb0210e9c585e9e05bf40ea7aef2  packer_1.4.1_freebsd_amd64.zip
    1f74851a732b550dee445e53af1d31e175c0008d000609188fbc05542ea7c817  packer_1.4.1_freebsd_arm.zip
    20ca7ed8120a37867cbd8b9293f0b28649445f607d0754fddee47595d811ca62  packer_1.4.1_linux_386.zip
    b713ea79a6fb131e27d65ec3f2227f36932540e71820288c3c5ad770b565ecd7  packer_1.4.1_linux_amd64.zip
    2a57bf77fc7b9f52195ac4b84fd5fc890e7356dbc97154507d54de2d7030fa1b  packer_1.4.1_linux_arm.zip
    b8d2f264f0e4760346a9848f73fcbfba2907db97778d9dbb2f70d20411518b74  packer_1.4.1_linux_arm64.zip
    743c6cf9169914730692d6fc8cdb7ecbf400a63213f327753853e888ad44e5df  packer_1.4.1_linux_mips.zip
    ecd290c7a7d8b28d816066241a7c929bafd88468869d17950d2802c4ac52a30a  packer_1.4.1_linux_mips64.zip
    4dbd7362f10580ef06a5a98762ae3781043319b888de2b527101977dce29b673  packer_1.4.1_linux_mipsle.zip
    889c2a4637f92f14858b395c62c73eaac0dbd88d92ff898472739cb7493f0f77  packer_1.4.1_linux_ppc64le.zip
    bccf4fba24fddfd9d9a062e1ac4b360d2e86a7f3269cac0136a34646bae14fdb  packer_1.4.1_linux_s390x.zip
    f2d47e5e13b899ac41e4c1639fc68efa877f748cce3f9cffc06b74d09552d8c6  packer_1.4.1_openbsd_386.zip
    74792d0ec9897e0b8740e4cf03e767aeee5e6b8e3233c9463bd663a921c26017  packer_1.4.1_openbsd_amd64.zip
    5aded26308d05b3b3b256ba160dd190cee73aa4cd8461c12af5990d5a137f27f  packer_1.4.1_solaris_amd64.zip
    943a3fd48b86cbc9e0014358d0cf662aa6827315ac61c613de62eb4cd59ae6e7  packer_1.4.1_windows_386.zip
    78416314aecbc166486fd8a7784523436c5c8673a1788047b14140f43977d72c  packer_1.4.1_windows_amd64.zip

EOF

node.default['packer']['1.4.2']['prefix'] = "packer_"
node.default['packer']['1.4.2']['raw_checksums'] = <<-EOF
    7f7e134c268e68de3f426deb17fdb2baa8d75bfd0a055fa754cde35195d4dec7  packer_1.4.2_darwin_386.zip
    4e9bf72be16b00953dd7213e19fba97de569b91d8b8116b190efd647efe7d047  packer_1.4.2_darwin_amd64.zip
    0977e5237a2c64575860142c23daadfd906b78f887a979d2a881550f7cff2f56  packer_1.4.2_freebsd_386.zip
    63617c9de21f2b393edfbb875c82702335cb53449e68ad4171826b68054c967c  packer_1.4.2_freebsd_amd64.zip
    cc1ce3869872c8022751985c3d91c1f7780224de87404fe0cc1c76dab2c5d99c  packer_1.4.2_freebsd_arm.zip
    30e26eb19cef96bc759df42e4fb2a15399b45a121af900c589e110953a607197  packer_1.4.2_linux_386.zip
    2fcbd1662ac76dc4dec381bdc7b5e6316d5b9d48e0774a32fe6ef9ec19f47213  packer_1.4.2_linux_amd64.zip
    b883a6f0da25ce9aef2ed722bf32cf94fcdaf35f8652093b866c9b40efc38fbe  packer_1.4.2_linux_arm.zip
    58d6b853186f9cd8d55f07b88f65d01e12926cc4c46d270bef2f5c1da3da5cd7  packer_1.4.2_linux_arm64.zip
    55f919f27471960da70dc0f83f419cf490ea7704dc521652cf4e1947cc1d2dd0  packer_1.4.2_linux_mips.zip
    7f49b0178f997e5b0f41f133db8ab3fd05ab425f48bedbed26b726db35fe75eb  packer_1.4.2_linux_mips64.zip
    e2c1e16879dc03b602d067761d48a4de5378499495481f66ca4d93d7a7805a38  packer_1.4.2_linux_mipsle.zip
    01e66485ace04c4404017a8646f785440418b0ec935a4873bfef39b8aefc7074  packer_1.4.2_linux_ppc64le.zip
    02000defc62f0c4eeee1d11dfe6f5f4eea47f96dd7ba6d25ae72fd9038b06836  packer_1.4.2_linux_s390x.zip
    d1975d4fddd2eebfbeedf57af47cb3a97464c8b204988d11194b86c84ea65a52  packer_1.4.2_openbsd_386.zip
    6ffbe317443cc335be56df6ee87f58d4616cebacc8795542d6ce0b0b66c7a6f3  packer_1.4.2_openbsd_amd64.zip
    0aa5b593f9021a81aae8b53f90c346d68fc40e6fdf6e50ce702b2a67a2a80bbd  packer_1.4.2_solaris_amd64.zip
    dfd8c17a1ad6a1c5cbeb9f9bee220fd45ff3c877186ec1e571f5a3ed646f5284  packer_1.4.2_windows_386.zip
    0db7527e81672d51fc436081eff0e49e8873baee0564e427c5dc73a3f44fa840  packer_1.4.2_windows_amd64.zip
EOF

node.default['packer']['1.4.3']['prefix'] = "packer_"
node.default['packer']['1.4.3']['raw_checksums'] = <<-EOF
    d892c163c6fc1c10b7784a04664a9235e06df830f760d98f84910842a4192875  packer_1.4.3_darwin_386.zip
    9b479c5442f81991eda777445fd07cc4582c573989863c2df56268b2db791bbc  packer_1.4.3_darwin_amd64.zip
    5f6c4abc924a67b985fea04175c9b44a9b64b6e474de9630357d4bf06e9e597b  packer_1.4.3_freebsd_386.zip
    773619f22b3205137aa9d5bda109637ec1aab379e1cf9933320da79cf985d0d2  packer_1.4.3_freebsd_amd64.zip
    eb79bba27ea71b5c64acf94cfbbe5a2e34f35f16c091c4f1c86937c309f55d47  packer_1.4.3_freebsd_arm.zip
    53ea97ec6f7f92520e2b4a9a2fcb3a4a8b8239711b24bccc489c1528a7acc561  packer_1.4.3_linux_386.zip
    c89367c7ccb50ca3fa10129bbbe89273fba0fa6a75b44e07692a32f92b1cbf55  packer_1.4.3_linux_amd64.zip
    cd792228fb45d16ec0748208aa91802c3559649cf678aebde2f1f98de71f42a2  packer_1.4.3_linux_arm.zip
    672c9c7c6e56bd0c4d9c1df870c2d985522492624024be1b175b8f4697ad1d38  packer_1.4.3_linux_arm64.zip
    c04279b110be823fb1c5f284c7b894a6c19699d2367bf3ffcb128aa7eb9aea66  packer_1.4.3_linux_mips.zip
    5fd113f504bc4af31160552365c043c3c207a91e7a773f0f3c5431841a96cb5e  packer_1.4.3_linux_mips64.zip
    44a48994b19be56afd1cbea3a443038c428e53ebd7e6f7cdbd0331a0c926e83c  packer_1.4.3_linux_mipsle.zip
    e2c9674fcfa702c95785b77d665cf505093288de8bcf5e72ac8b204edf88e9ba  packer_1.4.3_linux_ppc64le.zip
    029156a00bc70473157fdd5189223e7d802f18e86acf1a34475a2546bced08d9  packer_1.4.3_linux_s390x.zip
    8394328174eb166250261763b872ad29f839fa650cf90177cbd89f2200401678  packer_1.4.3_openbsd_386.zip
    6cffbd51003f7f3670331242e95df413d496d40fb82f86168230a718128130e3  packer_1.4.3_openbsd_amd64.zip
    bdd1bd14f4d03d7303cf35992b44488e57b95add2c71d3ee41ccb9b817dd3ce2  packer_1.4.3_solaris_amd64.zip
    46d1fbb4a6e8afe65164fcbaaa08ac21bddc4a0b2f8f9ce25d6586172c0bbb41  packer_1.4.3_windows_386.zip
    9df329285c46bb3e64462c7a6f2f0673b227466564ff1b6739d930d3aee719fe  packer_1.4.3_windows_amd64.zip
EOF


node.default['packer']['1.4.4']['prefix'] = "packer_"
node.default['packer']['1.4.4']['raw_checksums'] = <<-EOF
    584378edfb361f45763c257e480a4b68b38ef4cf9a2154c163d4195539b010f8  packer_1.4.4_darwin_386.zip
    d57c8ecc3b4356b176e600e4de420fc3feba1ca0d95693dfabb0860145b720b1  packer_1.4.4_darwin_amd64.zip
    095d72add4692e3aba9bd61f8fce17bd8343560ddbd05fd5273f7b4b392979d8  packer_1.4.4_freebsd_386.zip
    e47841c124a6e71f0711f0bb9e020f3279470ad33933a58545d7a68e2a36aa61  packer_1.4.4_freebsd_amd64.zip
    a1a3773305453c81c48a5f5c0d2df91d64a44c29063e3d5dccd6be77fef3bcea  packer_1.4.4_linux_386.zip
    b4dc37877a0fd00fc72ebda98977c2133be9ba6b26bcdd13b1b14a369e508948  packer_1.4.4_linux_amd64.zip
    0cac826f983172aa836da65f76aa535fe7eacdece0510832ccfe3b51cb8dfe47  packer_1.4.4_linux_arm.zip
    c6930cf5afdeb99df3ed5c9eeeef89fbcb3a1a71a9e17ebba16c873405ab72cd  packer_1.4.4_linux_arm64.zip
    f8fb352c9a036617f2250c9bdb60ac29cecaafcd64da4c65b4805883e26f8f2b  packer_1.4.4_linux_mips.zip
    1c946178edd341bb4765dee76e60164c33d0251ef80331e8a754da6965b78cc9  packer_1.4.4_linux_mips64.zip
    83956733c86717acf0ccb65cf64ea8b338e0c13395314a7615339047125eae13  packer_1.4.4_linux_mipsle.zip
    88810d5f07db78e87c062325abf6ef332cc7025d02dcbac54eaecff31962be4c  packer_1.4.4_linux_ppc64le.zip
    a8ce4d557763431ff56cf3c0d40aa753fe1408492a612b2dff0295c629943bce  packer_1.4.4_linux_s390x.zip
    f69c02cfec16aefa0c4e6d35eda84aaf3b2873658383f565a2e8785856217d84  packer_1.4.4_openbsd_386.zip
    7f21fb2ee4e8adfeaf96c53df02aa09f223cf2ebeadaf63bd2402de904e465bd  packer_1.4.4_openbsd_amd64.zip
    6b7a7ddb7deab30d7ae804bb3ef0aed1a0133d315f0802331593d849a80ae4cf  packer_1.4.4_solaris_amd64.zip
    2cb20b287c3063d45fb820a3973992ff5ae6269a90caf39945b133b64966f16a  packer_1.4.4_windows_386.zip
    310a98e6ac7d4ee4f306a5f8385628a2e79a2cb8f7d2e894379e3a97ff5ed35b  packer_1.4.4_windows_amd64.zip
EOF

node.default['packer']['1.4.5']['prefix'] = "packer_"
node.default['packer']['1.4.5']['raw_checksums'] = <<-EOF
    91ac2b952fb1c7b13d8b42686823cad4d39ec319ca23f603c27fd8e45fc3c5f8  packer_1.4.5_darwin_386.zip
    97328422361ad69553522786100a62a774eb2cebe0cd89cfb531b53efbf8c9f9  packer_1.4.5_darwin_amd64.zip
    0af8e0072985060d741aa30597dd0ebf99b308e614247fdeae17b00043e6ed5c  packer_1.4.5_freebsd_386.zip
    ffbb40d73f270197c63e733d49d5e641df7e0fa8defe152f765fdc6d957c34ef  packer_1.4.5_freebsd_amd64.zip
    8d0f70e9304ecdfd28f73154611e9cf6ecdca208cafce9ca23644b71a3c3d845  packer_1.4.5_linux_386.zip
    30da8dab9c526a6d15b037e2234f6f12cf3accfad77eb2c130738ec1a54cab6d  packer_1.4.5_linux_amd64.zip
    2d3698966c8dacb10d049e887f14efdb7d2bae4ebbac83f22c17483e70d67a48  packer_1.4.5_linux_arm.zip
    8a0c4fa7ba6545c9a27cb8d47bca6ce5fbcbabc72b37c4670d2a58e2bded3792  packer_1.4.5_linux_arm64.zip
    ac265918809907e142752a1c75ec329ce9a05cba163d7c52ed11fe1f5c8b180c  packer_1.4.5_linux_mips.zip
    80bb4b671e69c7b821c7fa1106c271c44106d4a3f955963d6cf2607699db80e5  packer_1.4.5_linux_mips64.zip
    e30138ad656308f3bbe4a702c7efbc4167790e9df2c146ad286c68f18d51f089  packer_1.4.5_linux_mipsle.zip
    0bb1725728a65f42eb7aec390534c864bb9ca93097729500108384b81eae2c8e  packer_1.4.5_linux_ppc64le.zip
    5681b164400eb6996df9ab3c984e871f63d2b5e1573c07fe63fc575fbcb4ecf1  packer_1.4.5_linux_s390x.zip
    27059486f6e2b3d2f4fa09d0ccab032338810addcf243dc8d4cc860e520a2630  packer_1.4.5_openbsd_386.zip
    8fe6851fa7611f01ada66857405c98a902edf0c7b2a48656125ead316af0ce28  packer_1.4.5_openbsd_amd64.zip
    426592efbb378afacc07bc5905362f8094372fb99102aead4f5fe70d0aaf1afb  packer_1.4.5_solaris_amd64.zip
    1036a77f5775a88e24c74340dc40f5f47a50165edc2675b5de3758b0775cb6cb  packer_1.4.5_windows_386.zip
    5da1b38beaad735a8b7390865d33e5f60d830fa93e5485f593aae2254dcc4ad8  packer_1.4.5_windows_amd64.zip
EOF



node.default['packer']['checksums'] = Hash[
    node['packer'][node['packer']['version']]['raw_checksums'].split("\n").collect { |s| s.split.reverse }
]
prefix = node['packer'][node['packer']['version']]['prefix']
filename = "#{prefix}#{node['packer']['version']}_#{node['os']}_#{node['packer']['arch']}.zip"
node.default['packer']['dist_filename'] = filename
node.default['packer']['checksum'] = node['packer']['checksums'][filename]

puts "filename : [#{filename}]"

