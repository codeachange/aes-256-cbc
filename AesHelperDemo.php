<?php
require_once 'AesHelper.php';

$aesHelper = new AesHelper('my_secret');
$str = 'hello aes';
$encStr = '+pnntLyNRvJIWv9m0NeWuQ==';
//$result = $aesHelper->encrypt($str);
$result = $aesHelper->decrypt($encStr);
var_dump($result);
