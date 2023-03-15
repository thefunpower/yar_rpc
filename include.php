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
    global $config;
    if($c['cookie_domain'] && $c['cookie_prefix']){
        if(strpos($config['host'],$c['cookie_domain'])!==false){
            $flag = true;
            $config['cookie_domain'] = trim($c['cookie_domain']);
            $config['cookie_prefix'] = trim($c['cookie_prefix']);  
        }
    }
    if(!$flag){
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
* 基类
*/ 
class plat{
    public $check_login = true;
    /**
    * 初始化
    */
    public function __construct(){
        $this->init();
    }
    /**
    * 设置COOKIE作用域
    * 判断是否登录，未登录跳到SSO登录 
    */
    public function init(){
        service_set_app_cookie_config();
        if($this->check_login){
            get_rpc_login();    
        }        
    } 
    /**
    * 登录检测
    * 使用token检测登录信息
    * $config['redirect_url'] = '/';
    */
    protected function login_use_token(){ 
        global $config;
        $token = g('token');
        $redirect_url = g('redirect_url')?:$config['redirect_url'];
        if($token){
            $data = json_decode(aes_decode($token),true);
            if($data && $data['code'] == 0 && $data['data']['user_id']){ 
                $err = $data['time']+10-time() > 0?false:true;
                $this->set_cookie($data['data'],$err); 
                jump($redirect_url);
            } 
        } 
    }
    /**
    * 设置COOKIE登录信息
    * [user] => yiiphp@foxmail.com
    * [type] => email
    * [created_at] => 2023-02-13 17:15:33
    * [user_id] => 2
    */
    protected function set_cookie($data,$err){ 
        $content = "请求异常，请返回原地址重新发起请求";
        if(!$data['user_id'] || !$data['user'] || !$data['type']){
            $err = true;
            $content = '已阻止非法请求，如有疑问请联系管理员';
        }
        if($err){
            $title = "登录异常";
            return view('error',[
                'title'=>$title,
                'content'=>$content
            ]); 
        }
        $time = time()+86400*365*10;
        cookie('sso_user_id',$data['user_id'],$time);
        cookie('sso_user_account',$data['user'],$time);
        cookie('sso_user_type',$data['type'],$time);
    } 
}
/**
* 获取登录后的信息
*/
function get_sso_logined_info(){
    global $sso_user;
    if(cookie('sso_user_id')){
        $sso_user = [
            'user_id'=>cookie('sso_user_id'),
            'user_account'=>cookie('sso_user_account'),
            'user_type'=>cookie('sso_user_type'),
        ];
        return $sso_user;
    }
}
 
/**
* 登录
*/
function get_rpc_login(){
  $url = host().'login/check';
  $rpc = get_service('service');
  $res = $rpc->get('sso'); 
  if(!cookie('sso_user_id')){
    jump($res['domain'].'login/index?redirect_url='.urlencode($url));
  }
}
/**
* 退出系统
*/
function get_rpc_logout(){
    remove_cookie("sso_user_id");
    remove_cookie("sso_user_account");
    remove_cookie("sso_user_type"); 
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
        $rpc_url = $rpc_url.'rpc_client/';
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
    $ak     = 'anonymous';
    $domain = host();  
    $client = new Yar_Client($rpc_url);  
    $client->SetOpt(YAR_OPT_HEADER, [
        "TOKEN:".$token,
        "AK:".$ak,
        "DOMAIN:".$domain,
        "YARTPYE:RSA",
    ]); 
    $client->SetOpt(YAR_OPT_CONNECT_TIMEOUT, 3000);   
    return $client; 
}



/**
* RPC 基类
*/
class rpc_service{ 
    //请求SERVER信息
    protected $data;
    //解密后数据
    protected $decrypt_data;

    public function __construct(){ 
        $this->data = [
            'type'  => $_SERVER['HTTP_YARTPYE'],
            'domain'=> $_SERVER['HTTP_DOMAIN'],
            'ak'    => $_SERVER['HTTP_AK'],
            'token' => $_SERVER['HTTP_TOKEN'],
        ];
    }
    /**
    * 运行RPC函数时会验证通讯是否允许
    */
    protected function run($call){ 
        $token = $this->data['token'];
        $ak = $this->data['ak'];
        $domain = $this->data['domain'];
        $type = $this->data['type'];
        if(!in_array($type,['RSA','AES'])){
            return [
                'msg' => '服务异常，错误发现在'.now(),
                'label'=> 1000,
                'code'=> 404
            ]; 
        }
        //RAS
        if($type == 'RSA'){
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
            $this->decrypt_data = $decrypt_data;
            if(!$decrypt_data){
                return [ 
                    'token'=>$token,
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
        if(!$token){
            return [
                'msg' => '通讯异常，错误发现在'.now(),
                'label'=> 1003,
                'code'=> 403
            ]; 
        }
        return $call();
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
        $class = db_get_one("rpc_pass_service",'ns',['slug'=>$name,'status'=>1]); 
        if($class && $class_name){
            $class = $class.'\\'.$class_name; 
        }       
    }  
    $class = str_replace("\\\\","\\",$class);
    if(class_exists($class)){ 
        $service = new Yar_Server(new $class());
        $service->handle();
    }else{
        json_error(['msg'=>'service '.$class.' is not exists']);
    } 
}
add_action("app.start",function(){
    global $router;
    // /rpc_client/sso/login_by_email
    $router->get('/rpc_client/(\w+)/(\w+)',function($rpc_name,$class_name){  
        yar_api_run($rpc_name,$class_name);
    }); 
    $router->post('/rpc_client/(\w+)/(\w+)',function($rpc_name,$class_name){   
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
