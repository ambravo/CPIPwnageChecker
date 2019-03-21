/////////////////////////////
// Pwnage-Checker-For-CPI  //
// Ariel Bravo Ayala       //
// 2019                    //
// MIT License             //
/////////////////////////////

import groovy.json.JsonSlurper
import com.sap.gateway.ip.core.customdev.util.Message
import com.sap.it.api.securestore.SecureStoreService
import com.sap.it.api.securestore.UserCredential
import java.security.*
import com.sap.it.api.ITApiFactory
import groovy.time.*

def Message processData(Message message) {
    def body = message.getBody(String)
    def secureStorageService =  ITApiFactory.getApi(SecureStoreService.class, null)
    
    def jsonSlurper = new JsonSlurper()
    def bodyObject = jsonSlurper.parseText(body)
    def output = new StringBuilder()
    def timeStart = new Date()

    output <<= '<html><head><title>CPI Pwnage Checker</title></head><body><h1>Your pwned credentials</h1>'
    output <<= '<table border="1"><tr><th>Kind</th><th>Credential</th><th>Username</th><th>Times compromised</th></tr>'

    bodyObject.d.results.each {
        def credentialDetails = it
        if (["default","successfactors","secure_param"].contains(credentialDetails.Kind)){
            String[] content
            def credential = secureStorageService.getUserCredential(credentialDetails.Name)
            def user = credential.getUsername().toString()
            def pass = credential.getPassword().toString()
            def hash = getSHA1(pass)
            def prefix = hash.substring(0,5)
            def suffix = hash.substring(5)

            def get = new URL("https://api.pwnedpasswords.com/range/"+prefix).openConnection();
            get.setRequestProperty("User-Agent", "Pwnage-Checker-For-CPI") //Required
            def getRC = get.getResponseCode()
            
            TimeDuration duration = TimeCategory.minus(new Date(), timeStart)
            sleep(1500 - duration.getMillis()) // Wait between each call
            timeStart = new Date()
            
            if(getRC.equals(200)) {
                def reader = new BufferedReader(new InputStreamReader(get.getInputStream()))
                reader.eachLine {
                    content = it.split(":")
                    if (content[0] == suffix){
                        output <<= 
                            '<tr><td>' + credentialDetails.Kind +'</td>'+
                            '<td>' + credentialDetails.Name +'</td>'+
                            '<td>' + user +'</td>'+
                            '<td>' + content[1] +'</td></tr>'
                    }
                }
            }

        }
    }
    output <<= '</table><br><br>Copyright  2019 - Ariel Bravo Ayala - MIT License' 
    message.setHeader("Content-Type","text/html; charset=utf-8")
    message.setBody(output.toString())
    return message
}

def String getSHA1(String password){
    MessageDigest digest = MessageDigest.getInstance("SHA-1")
    digest.update(password.getBytes("UTF-8"))
    byte[] passwordDigest = digest.digest()
    String hexString = passwordDigest.collect { String.format('%02x', it) }.join()
    return hexString.toUpperCase()
}