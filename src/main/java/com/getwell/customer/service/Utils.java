package com.getwell.customer.service;

import com.getwell.customer.model.Role;
import com.getwell.customer.repositories.UserMongoRepository;
import com.getwell.customer.security.ApplicationUserDetails;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class Utils {
    @Autowired
    private UserMongoRepository userMongoRepository;
    @Autowired
    private Role role;
    @Autowired
    private JWTTokenUtils jwtTokenUtils;

    public String authenticateUser(HttpServletRequest request){
        String token = "";
        String upd = request.getHeader("authorization");
        String pair = new String(Base64.decodeBase64(upd.substring(6)));
        String userName = pair.split(":")[0];
        System.out.println("User name is "+userName);
        String password = pair.split(":")[1];
        System.out.println("password is "+password);
        String roleName = request.getParameter("role");
        if(roleName.equals("user")){
            role.setId(1);
            role.setName("user");
            var user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining(userName, password,role);
            if(user != null){
                String authToken = jwtTokenUtils.generateToken(new ApplicationUserDetails(user),"user");
                token = authToken;
            }
            else{
                token = "unauthenticated";
            }
        }
        else if(roleName.equals("vendor")){
            role.setId(2);
            role.setName("vendor");
            var user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining(userName, password,role);
            if(user != null){
                String authToken = jwtTokenUtils.generateToken(new ApplicationUserDetails(user),"vendor");
                token = authToken;
            }
            else{
                token = "unauthenticated";
            }
        }
        else{
            token = "unauthenticated";
        }
        return token;
    }

    public UserDetails getValidUserDetails(HttpServletRequest request){
        UserDetails userDetails = null;
        String token= request.getHeader("Authorization");
        if(token.startsWith("Basic")){
            String pair = new String(Base64.decodeBase64(token.substring(6)));
            String userName = pair.split(":")[0];
            String password = pair.split(":")[1];
            String roleName = request.getParameter("role");
            if (roleName.equals("user")) {
                role.setId(1);
                role.setName("user");
                var user = userMongoRepository.findByMobileNumberAndRolesContaining(userName, role);
                userDetails = new ApplicationUserDetails(user);
            } else if (roleName.equals("vendor")) {
                role.setId(2);
                role.setName("vendor");
                var user = userMongoRepository.findByMobileNumberAndRolesContaining(userName, role);
                userDetails = new ApplicationUserDetails(user);
            }
        }
        else {
            String jwtToken = new String((token.substring(7)));
            System.out.println(jwtToken);
            String userName = jwtTokenUtils.getUsernameFromToken(jwtToken);
            String roleName = jwtTokenUtils.getRoleFromToken(jwtToken);
            if (roleName.equals("user")) {
                role.setId(1);
                role.setName("user");
                var user = userMongoRepository.findByMobileNumberAndRolesContaining(userName, role);
                userDetails = new ApplicationUserDetails(user);
            } else if (roleName.equals("vendor")) {
                role.setId(2);
                role.setName("vendor");
                var user = userMongoRepository.findByMobileNumberAndRolesContaining(userName, role);
                userDetails = new ApplicationUserDetails(user);
            }
        }
        return userDetails;
    }
}
