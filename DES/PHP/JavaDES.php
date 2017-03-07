<?php

class JavaDES
{
    public $key;
    public $encoder = 'hex';//base64

    /**
     * [__construct description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T14:00:20+0800
     * @param    [type]                   $key     [description]
     * @param    string                   $encoder [description]
     */
    public function __construct($key, $encoder='hex') {
        $this->key = $key;
        $this->encoder = $hex;
    }

    /**
     * [encrypt description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T13:59:42+0800
     * @param    [type]                   $input [description]
     * @return   [type]                          [description]
     */
    public function encrypt($input) {
        $size = mcrypt_get_block_size('des', 'ecb');
        $input = $this->pkcs5_pad($input, $size);
        $key = $this->key;
        $td = mcrypt_module_open('des', '', 'ecb', '');
        $iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        @mcrypt_generic_init($td, $key, $iv);
        $data = mcrypt_generic($td, $input);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        $data = $this->encoder==='hex' ? bin2hex($data) : base64_encode($data);         
        return $data;
    }

    /**
     * [decrypt description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T13:59:49+0800
     * @param    [type]                   $encrypted [description]
     * @return   [type]                              [description]
     */
    public function decrypt($encrypted) {
        $encrypted = $this->encoder==='hex' ? hex2bin($encrypted) : base64_decode($encrypted);       
        $key =$this->key;
        $td = mcrypt_module_open('des','','ecb','');
        //使用MCRYPT_DES算法,cbc模式                
        $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
        $ks = mcrypt_enc_get_key_size($td);
        @mcrypt_generic_init($td, $key, $iv);
        //初始处理                
        $decrypted = mdecrypt_generic($td, $encrypted);
        //解密              
        mcrypt_generic_deinit($td);
        //结束            
        mcrypt_module_close($td);
        $y=$this->pkcs5_unpad($decrypted);
        return $y;
    }

    /**
     * [pkcs5_pad description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T13:59:53+0800
     * @param    [type]                   $text      [description]
     * @param    [type]                   $blocksize [description]
     * @return   [type]                              [description]
     */
    public function pkcs5_pad ($text, $blocksize) {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }

    /**
     * [pkcs5_unpad description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T14:00:01+0800
     * @param    [type]                   $text [description]
     * @return   [type]                         [description]
     */
    public function pkcs5_unpad($text) {
        $pad = ord($text{strlen($text)-1});
        if ($pad > strlen($text))
            return false;
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
            return false;
        return substr($text, 0, -1 * $pad);
    }

    /**
     * [hex2bin description]
     * @Author   WirrorYin
     * @DateTime 2017-03-07T14:00:06+0800
     * @param    boolean                  $hex [description]
     * @return   [type]                        [description]
     */
    public function hex2bin($hex = false){
        $ret = $hex !== false && preg_match('/^[0-9a-fA-F]+$/i', $hex) ? pack("H*", $hex) : false;
        return $ret;
    }
}