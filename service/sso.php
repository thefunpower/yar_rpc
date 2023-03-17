<?php 
/*
    Copyright (c) 2021-2031, All rights reserved.
    This is NOT a freeware
    LICENSE: https://github.com/thefunpower/core/blob/main/LICENSE.md 
    Connect Email: sunkangchina@163.com
*/

/**
* 获取登录后的信息
*/
function get_sso_logined_info(){
    //service_set_app_cookie_config();
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
function sso_service_login(){
  $url = host().'sso/login/check';
  $rpc = get_service('service');
  $res = $rpc->get('sso'); 
  if(!cookie('sso_user_id')){
     $return_url = '';
     $jump = $_SERVER['REQUEST_URI']; 
     if($jump){
        if(substr($jump,0,1) == '/'){
            $jump = substr($jump,1);
        }
        $return_url = host().$jump;
     }  
     $new_url = $res['domain'].'sso/login/index?redirect_url='.urlencode($url);
     if($return_url){
        $new_url = $new_url.'&return_url='.urlencode($return_url);
     }
     jump($new_url);
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

add_action("app.start",function(){
    global $router;
    $router->get("/sso/login/check",function()
    {
        sso_login_return();
    });
}); 

function sso_login_return(){
    $token = g('token');
    $data = json_decode(aes_decode($token),true); 
    $return_url = g('return_url')?:$config['return_url']; 
    if($token){
        $data = json_decode(aes_decode($token),true); 
        if($data && $data['code'] == 0 && $data['data']['user_id']){ 
            $err = $data['time']+10-time() > 0?false:true;
            sso_login_set_cookie($data['data'],$err); 
            jump($return_url?:'/');
        }else{
            exit('Token Error');
        }
    }else{
        exit('Request Failed');
    }
}

function sso_login_set_cookie($data,$err){
    //service_set_app_cookie_config();
    $content = "请求异常，请返回原地址重新发起请求";
    if(!$data['user_id'] || !$data['user'] || !$data['type']){
        $err = true;
        $msg = '已阻止非法请求，如有疑问请联系管理员';
        return;
    } 
    $time = time()+86400*365*10;
    cookie('sso_user_id',$data['user_id'],$time);
    cookie('sso_user_account',$data['user'],$time);
    cookie('sso_user_type',$data['type'],$time);
}

