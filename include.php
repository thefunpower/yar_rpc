<?php 
/*
    Copyright (c) 2021-2031, All rights reserved.
    This is NOT a freeware
    LICENSE: https://github.com/thefunpower/core/blob/main/LICENSE.md 
    Connect Email: sunkangchina@163.com
*/
/**
*  RPC 服务 
*/ 

/**
* 检测使用服务，用户是否登录
*/
function service_check_login(){
    if(!cookie('sso_user_id') || !cookie('sso_user_account')){
        echo '<div style="margin:auto;text-align: center;font-size: 18px;margin-top: 20px;color: red;">403访问被禁止</div>';
        exit;
    }
}
/**
* 获取服务配置
*/
function service_set_service_cookie_config(){ 
    //如 sso.test.com
    $host = $_SERVER['HTTP_HOST'];
    $domain = substr($host,strpos($host,'.'));
    $rpc = get_service('config');
    $c   = $rpc->get_by_cookie_domain($domain);
    __plat_cookie_get($c);
}
/**
 * 设置应用COOKIE信息
*/
function service_set_app_cookie_config(){
    global $config;
    $flag = false;
    $rpc = get_service('app');
    $c = $rpc->get_config($config['host']);
    __plat_cookie_get($c);
}
/**
* 内部函数，COOKIE根域名判断
*/
function __plat_cookie_get($c){
    //cookie暂不用配置
    return;
    global $config; 
    if($c['cookie_domain'] && $c['cookie_prefix']){
        if(strpos($config['host'],$c['cookie_domain'])!==false){
            $flag = true;
            //$config['cookie_domain'] = trim($c['cookie_domain']);
            $config['cookie_prefix'] = trim($c['cookie_prefix']);  
        }
    } 
    if(!$flag){
        if(is_json_request()){
            json_error(['msg'=>'应用未注册或未正确配置域名信息']);
        }
        die("
            <div style='color:red;'>访问被中止！<br>请在软件平台控制中心正确配置当前应用根域名信息!</div>
        ");
    }
}
/**
* 获取服务域名
*/
function get_service_url($service_name){
  $res = get_service_info($service_name);
  return $res['domain'];
}
/**
* 获取服务信息
*/
function get_service_info($service_name){
  $client = get_service('service');
  if(!$client){return;}
  $res = $client->get('sso');
  return $res;
} 
/**
* 初始化服务中心
* 需要生成RSA证书
*/ 
function plat_boot_rsa(){
    $privatekey = PATH.'data/privatekey.pem';
    $publickey = PATH.'data/publickey.pem';
    if(!file_exists($privatekey)){
        $rsa = new lib\Rsa;
        $res = $rsa->create(); 
        file_put_contents($privatekey,$res['privatekey']);
        file_put_contents($publickey,$res['publickey']);
    }else{

    } 
}
/**
* 注册服务到RPC服务中心
*/
function register_service($app_name,$slug){ 
    register_app($app_name,'service',$slug);
}

/**
* 把软件注册到RPC服务中心
* register_app('演示');
*/
function register_app($app_name,$type = 'app',$slug = ''){ 
    $service= get_service('app'); 
    $domain = host();  
    try {
        $res = $service->register($app_name, $domain,$type,$slug);
        if($res['ak'] && $res['sk']){ 
            unset($res['ak'],$res['sk']);  
        } 
    } catch (Exception $e) {
        if(is_cli()){
            echo $e->getMessage();exit;    
        }        
        log_error($e->getMessage());
    } 
}


/**
* 通过RSA方法请求RPC服务
* RSA用公钥加密
* 向RPC服务中心请求的
*/
function get_service($service_name,$rpc_url='',$class_name = ''){ 
    global $config;
    $rpc_url = $rpc_url?:$config['rpc_service_url'];
    //RPC服务中心自带的服务
    $rpc_service_in = rpc_service_in(); 
    if(!in_array($service_name,$rpc_service_in)){
        $rpc_url = $rpc_url.'rpc_service/';
        if($class_name){ 
            $rpc_url = $rpc_url.$service_name.'/'.$class_name; 
        }
    }else{
        $rpc_url = $rpc_url.$service_name;
    }
    $publickey = PATH.'data/publickey.pem';
    if(!file_exists($publickey)){
        json_error(['msg'=>'RSA publickey file not exists']);
    } 
    $publickey = file_get_contents($publickey); 
    $rsa = new lib\Rsa;
    $token = base64_encode($rsa->encode(json_encode([
        'time'=>time(),
        'api_name'=>$service_name,
    ]),$publickey));  
    $domain = host();  
    $client = new Yar_Client($rpc_url);  
    $client->SetOpt(YAR_OPT_HEADER, [
        "Authorization: Bearer ".$token, 
        "DOMAIN:".$domain 
    ]); 
    //RPC是不是远程的服务,默认调用本地的服务
    if($config['rpc_is_remote']){

    }else{
        $client->SetOpt(YAR_OPT_RESOLVE, array("host:80:127.0.0.1"));    
    }   
    if(YAR_VERSION >= '2.3.0'){
        $client->setOpt(YAR_OPT_PROVIDER, "provider");
        $client->setOpt(YAR_OPT_TOKEN, $token);   
    } 
    $client->SetOpt(YAR_OPT_CONNECT_TIMEOUT, 3000);   
    do_action("rpc.client",$client);  
    return $client; 
}


/**
* header auth
*/
function rpc_auth_bearer(){
    $token = trim($_SERVER['HTTP_AUTHORIZATION']);
    if(strpos($token,'Bearer')!==false){
        $token = substr($token,strlen('Bearer'));
    }
    $data = [ 
        'domain'=> $_SERVER['HTTP_DOMAIN'], 
        'token' => $token,
    ]; 
    if(!$token){
        return [
            'msg' => '通讯异常，错误发现在'.now(),
            'label'=> 1003,
            'code'=> 403
        ]; 
    }
    //RAS 
    $privatekey = PATH.'data/privatekey.pem';
    if(!file_exists($privatekey)){
        return [
            'msg'  => '通讯证书异常，错误发现在'.now(),
            'label'=> 1001,
            'code' => 403
        ]; 
    }
    $privatekey = file_get_contents($privatekey);
    $rsa = new lib\Rsa;   
    $b_token = base64_decode($token); 
    $decrypt_data = json_decode(@$rsa->decode($b_token,$privatekey),true);
    if(!$decrypt_data){
        return [ 
            'token'=> $token,
            'msg'  => '通讯证书异常，错误发现在'.now(),
            'label'=> 1002,
            'code' => 403
        ]; 
    }
    if(!$decrypt_data['time']){
        return [  
            'msg'  => '请求异常，错误发现在'.now(),
            'label'=> 10020,
            'code' => 403
        ]; 
    }
    if( $decrypt_data['time']+10 > time()){
        
    }else{
        return [  
            'msg'  => '请求异常，错误发现在'.now(),
            'label'=> 10021,
            'code' => 403
        ]; 
    }   
}

/**
* RPC 基类
*/
class rpc_service{ 
    public $err;
    public function __construct(){ 
        if(YAR_VERSION >= '2.3.0'){
        }else{
            $err = rpc_auth_bearer();  
            log_error('YAR_VERSION 需要 2.3.0或以上版本，当前版本为'.YAR_VERSION);
            log_error($err);
        } 
    }  
    /**
     * yar auth
     */
    protected function __auth($provider, $token) { 
        $err = rpc_auth_bearer();  
        if($err){
            return false;
        }else{
            return true;    
        }
    }
}
/**
* 调用服务
*/
function get_api_service($service,$class_name,$call){ 
    //服务中心查寻对应的服务服务是否已注册并启用
    $client = get_service('service');  
    $res = $client->get($service);   
    //取到所需服务对应的接口域名，并发起RPC请求
    if($res['code'] == 0 && $res['domain']){   
        $client = get_service($service,$res['domain'],$class_name);  
        return $call($client);
    }else{

    } 
}
function rpc_service_in(){
    $rpc_service_in = [
        'app',
        'config',
        'mail',
        'service',
        'sms',
    ];
    do_action("rpc.service",$rpc_service_in);
    return $rpc_service_in;
}
/**
* 执行
*/
function yar_api_run($name,$class_name = ''){
    //RPC服务中心自带的服务
    $rpc_service_in = rpc_service_in(); 
    if(in_array($name,$rpc_service_in)){
        $class = '\plugins\\rpc_service\\service\\'.$name;
    }else{ 
        $class = "\plugins\\rpc_".$name."\\service";
        if($class_name){
            $class = $class.'\\'.$class_name; 
        }    
    }  
    $class = str_replace("\\\\","\\",$class); 
    if(class_exists($class)){
        $service = new Yar_Server(new $class);
        $service->handle();
    }else{
        json_error(['msg'=>'service '.$class.' is not exists']);
    } 
}
add_action("app.start",function(){
    global $router;
    // /rpc_service/sso/login_by_email
    $router->get('/rpc_service/(\w+)/(\w+)',function($rpc_name,$class_name){  
        yar_api_run($rpc_name,$class_name);
    }); 
    $router->post('/rpc_service/(\w+)/(\w+)',function($rpc_name,$class_name){   
        yar_api_run($rpc_name,$class_name);
    });  
});
/**
 * 设置应用或服务配置
 */
function plat_set_config($title, $body,$table='config',$where = [])
{
    if(in_array($title,[
        '_timestamp',
        '_signature',
    ])){
        return;
    }
    $one = db_get_one($table, "*", ['title' => $title]+$where); 
    if (!$one) {
        $insert = ['title' => $title, 'body' => $body];
        if($where){
            $insert =  $insert+$where;
        }
        db_insert($table, $insert);
    } else {
        db_update($table, ['body' => $body], ['id' => $one['id']]);
    }
}
/**
 * 获取应用或服务配置
 */
function plat_get_config($title,$table='config',$where = [])
{
    global $config;
    if (is_array($title)) {
        $list = [];
        $all  = db_get($table, "*", ['title' => $title]+$where);
        foreach ($all as $one) {
            $body = $one['body']; 
            $list[$one['title']] = $body ?: $config[$one['title']];
        }
        return $list;
    } else {
        $one  = db_get_one($table, "*", ['title' => $title]+$where);
        $body = $one['body'];
        if (!$body) {
            return $config[$title];
        } 
        return $body; 
    }
}