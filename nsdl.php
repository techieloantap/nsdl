<?php
namespace aw2\nsdl;

/**
	Desc : This will return an array
	Input: 
		pan_card   : <string>
		data['input_file_name'] : <string>
        data['output_file_name'] : <string>
        data['signature_pem_path'] : <string>

**/



\aw2_library::add_service('nsdl.pan_verify','NSDL PAN Card Verification',['namespace'=>__NAMESPACE__]);
function pan_verify($atts,$content=null,$shortcode){

    if(\aw2_library::pre_actions('all',$atts,$content,$shortcode)==false)return;
	extract( shortcode_atts( array(
		'pan_card'=>'',
		'config'=>''
		), $atts) );	

    $error=array('status'=>'error','message'=>'Config is should not be empty');
	if(empty($config) || !(is_array($config)) ){
		return $error;
	}
	$error=array('status'=>'error','message'=>'Client id is missing in config');
	if(!isset($config['client_id']) || $config['client_id']==''){
		return $error;
	}
		
	$token =md5(time() . rand()); 
	$data = $config['client_id'].$pancard;
	$inputfilename=$config['input_file_name'].$token."_i.txt";
	$outputfilename=$config['output_file_name'].$token."_o.txt";

	$fp = fopen($inputfilename, "w");
	fwrite($fp, $data);
	fclose($fp);

	$rs=array();
	$rs['status']="Failed"; 
	$rs['data']=""; 
	$return_value= $rs;
	
	if (openssl_pkcs7_sign($inputfilename, $outputfilename, "file://".realpath($config['signature_pem_path']),
    "file://".realpath($config['signature_pem_path']),array())) {
			// message signed - send it!

			$content = file_get_contents($outputfilename);
			$regex="/(?s)Content-Disposition(?:.*?)\n\n(.*?)\n\n/";
			preg_match($regex, $content, $matches, PREG_OFFSET_CAPTURE);
			
			
			$signature= $matches[1][0];
			$arr=array();
			$arr["data"]=$data;
			$arr["signature"]=$signature;
			$arr["version"]='2';

			
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL,$config['url']);
			curl_setopt($ch, CURLOPT_POST, 1);
			curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query($arr));
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);	

			// receive server response ...
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			
		
			$server_output = curl_exec ($ch);

			if (curl_errno($ch)) {
				$error=array('status'=>'error','message'=>'Request Error: ' .curl_error($ch));
				return $error;
			}

			curl_close ($ch);
			
			if (strpos($server_output, '1') === 0) {
				   // It starts with '1'
				 $rs['status']="success";  
				 $rs['data']=$server_output;  
			}else{
				$rs['status']="Failed"; 
				$rs['data']=$server_output; 
			}
			
			$return_value= $rs;
		}
	
	return $return_value;

}