package com.getwell.customer.controller;

import com.getwell.customer.model.Role;
import com.getwell.customer.model.User;
import com.getwell.customer.repositories.UserMongoRepository;
import com.getwell.customer.security.ApplicationUserDetails;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.List;

@RestController
public class CustomerController {
    @Autowired
    private User user;
    @Autowired
    private Role role;
    @Autowired
    private UserMongoRepository userMongoRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("loginEr")
    public String encoding(@RequestParam("pass") String pass) {
        String password = passwordEncoder.encode(pass);
        System.out.println(password);
        boolean check = passwordEncoder.matches(pass, password);
        System.out.println(check);
        return null;
    }

    @GetMapping("login")
    public String logInUser(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletRequest request) {
        return "Authenticated";
    }

    @GetMapping("loginVendor")
    public String logInVendor(@RequestParam("username") String username, @RequestParam("password") String password, HttpServletRequest request){
        String status = "";
        role.setId(2);
        role.setName("vendor");
        user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining(username, password, role);
        if(user != null){
            UserDetails principal = new ApplicationUserDetails(user);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
            SecurityContext securityContext = SecurityContextHolder.getContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            // Create a new session and add the security context.
            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
            status = "authenticated";
        }
        else{
            status = "failed";
        }
        return status;
    }

    @GetMapping("userTest")
    public String userTesting(HttpServletRequest request, @RequestParam("role") String roleName){
        String auth = request.getHeader("Authorization");
        return "User test is going on.....";
    }

    @GetMapping("userTest1")
    public String userTesting1(){
        return "User test 1 is going on ....";
    }

    @GetMapping("vendorTest")
    public String vendorTesting(@RequestParam("role") String roleName){
        role.setId(1);
        role.setName("user");
        user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining("01720024944","123456",role);
        System.out.println("Role id is "+user.getId());
        return "vendor test is going on...";
    }


    @GetMapping("logout")
    public String logout(HttpSession httpSession){
        String status = "";
        try {
            httpSession.invalidate();
            SecurityContextHolder.clearContext();
            status = "success";
        } catch (Exception e) {
            e.printStackTrace();
            status = "failed";
        }
        return status;
    }
}
