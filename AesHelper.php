<?php

class AesHelper {
    private $key;
    private $iv;

    function __construct($secret) {
        $keyAndIv = $this->EVP_BytesToKey(32, 16, null, $secret, 1);
        $this->key = pack('c*', ...$keyAndIv[0]);
        $this->iv = pack('c*', ...$keyAndIv[1]);
    }

    public function encrypt($text) {
        $result = openssl_encrypt($text, 'AES-256-CBC', $this->key, 0, $this->iv);
        return $result;
    }

    public function decrypt($base64Text) {
        $result = openssl_decrypt($base64Text, 'AES-256-CBC', $this->key, 0, $this->iv);
        return $result;
    }

    private function EVP_BytesToKey(int $key_len, int $iv_len, $salt, String $data, int $count) {
        $key = [];
        $key_ix = 0;
        $iv = [];
        $iv_ix = 0;
        $md_buf = null;
        $nkey = $key_len;
        $niv = $iv_len;
        $addmd = 0;
        for (;;) {
            $md = hash_init('md5');
            if ($addmd++ > 0) {
                hash_update($md, pack('c*', ...$md_buf));
            }
            hash_update($md, $data);
            if (null != $salt) {
                hash_update($md, substr($salt, 0, 8));
            }
            $md_buf = $this->hash_final_bytes($md);
            for ($i = 1; $i < $count; $i++) {
                $md = hash_init('md5');
                hash_update($md, pack('c*', ...$md_buf));
                $md_buf = $this->hash_final_bytes($md);
            }
            $i = 0;
            if ($nkey > 0) {
                for (;;) {
                    if ($nkey == 0)
                        break;
                    if ($i == count($md_buf))
                        break;
                    $key[$key_ix++] = $md_buf[$i];
                    $nkey--;
                    $i++;
                }
            }
            if ($niv > 0 && $i != count($md_buf)) {
                for (;;) {
                    if ($niv == 0)
                        break;
                    if ($i == count($md_buf))
                        break;
                    $iv[$iv_ix++] = $md_buf[$i];
                    $niv--;
                    $i++;
                }
            }
            if ($nkey == 0 && $niv == 0) {
                break;
            }
        }
        for ($i = 0; $i < count($md_buf); $i++) {
            $md_buf[$i] = 0;
        }
        $both[0] = $key;
        $both[1] = $iv;
        return $both;
    }

    private function hash_final_bytes($ctx) {
        return array_values(unpack('c*', hash_final($ctx, true)));
    }
}
