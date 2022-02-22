package com.getwell.customer.security;

import com.getwell.customer.model.Role;
import com.getwell.customer.model.User;
import com.getwell.customer.repositories.UserMongoRepository;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private Role role = new Role();
    private User user = new User();
    private UserMongoRepository userMongoRepository;

    public AuthenticationFilter(UserMongoRepository userMongoRepository){
        super();
        this.userMongoRepository = userMongoRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        /*String auth = request.getHeader("Authorization");
        String upd = request.getHeader("authorization");
        String pair = new String(Base64.decodeBase64(upd.substring(6)));
        String userName = pair.split(":")[0];
        String password = pair.split(":")[1];
        String roleName = request.getParameter("role");
        System.out.println("this role name is "+roleName);*/
        String userName = request.getParameter("username");
        String password = request.getParameter("password");
        String roleName = request.getParameter("role");
        Authentication authentication = null;
        if (roleName.equals("user")) {
            role.setId(1);
            role.setName("user");
            user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining(userName, password, role);
            if (user != null) {
                UserDetails principal = new ApplicationUserDetails(user);
                authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
                //SecurityContext securityContext = SecurityContextHolder.getContext();
                //securityContext.setAuthentication(authentication);
                //SecurityContextHolder.setContext(securityContext);
                // Create a new session and add the security context.
                //HttpSession session = request.getSession(true);
                //session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

                // Create a new session and add the security context.
                //HttpSession session = request.getSession(true);
                //session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
                System.out.println("User authentication is done ...");
            }
        }
        else if(roleName.equals("vendor")){
            role.setId(2);
            role.setName("vendor");
            user = userMongoRepository.findByMobileNumberAndPasswordAndRolesContaining(userName, password, role);
            if (user != null) {
                UserDetails principal = new ApplicationUserDetails(user);
                authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
                //SecurityContext securityContext = SecurityContextHolder.getContext();
               //securityContext.setAuthentication(authentication);
                //SecurityContextHolder.setContext(securityContext);
                // Create a new session and add the security context.
                //HttpSession session = request.getSession(true);
                //session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

                // Create a new session and add the security context.
                //HttpSession session = request.getSession(true);
                //session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
                System.out.println("Vendor authentication is done..");
            }
        }
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        chain.doFilter(request,response);
    }
}
