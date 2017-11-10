rule vault8_hived {
  meta:
    description = "Vault 8 Hive hived server implant"

  strings:
    // common
    $b0 = "Option K" fullword // server/main.c client/main.c
    $b1 = "./server.crt" fullword // common/crypto/crypto.h
    $b2 = "./ca.crt" fullword // common/crypto/crypto.h
    $b3 = "./server.key" fullword // common/crypto/crypto.h
    $b4 = ".seedfile" fullword // common/crypto/crypto.c

    // server
    $s0 = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" fullword // server/beacon.c
    $s1 = {b6 bb df 8b 90 90 df 8c 97 90 8d 8b FF} // server/main.c oe3

  condition:
    (all of ($b*)) and (all of ($s*))
}

rule vault8_hived_unpatched {
  meta:
    description = "Vault 8 Hive hived sever implant unpatched"

  strings:
    // server/main.c SIG_HEAD = 0x7AD8CFB6
    $h0 = { 7A D8 CF B6 } // big
    $h1 = { B6 CF D8 7A } // little

  condition:
    ($h0 or $h1) and vault8_hived
}
