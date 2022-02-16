package com.getwell.customer.security;

import com.getwell.customer.model.Role;
import com.getwell.customer.model.User;
import com.getwell.customer.repositories.UserMongoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class AuthorizationFilter extends BasicAuthenticationFilter {
    private User user = new User();
    private UserMongoRepository userMongoRepository;
    private Role role = new Role();

    public AuthorizationFilter(UserMongoRepository userMongoRepository, AuthenticationManager authenticationManager)
    {
        super(authenticationManager);
        this.userMongoRepository = userMongoRepository;

    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String userName  = "01720024944";
        String roleName = request.getParameter("role");
        System.out.println(roleName);
        if(roleName == "user"){
            role.setId(1);
            role.setName("user");
            user = userMongoRepository.findByMobileNumberAndRolesContaining(userName,role);
        }
        else{
            role.setId(2);
            role.setName("vendor");
            user = userMongoRepository.findByMobileNumberAndRolesContaining(userName,role);
        }
        System.out.println("numbeeer"+user.getMobileNumber());
        UserDetails principal = new ApplicationUserDetails(user);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        chain.doFilter(request, response);
    }
}
