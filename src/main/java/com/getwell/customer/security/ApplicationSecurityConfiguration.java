package com.getwell.customer.security;

import com.getwell.customer.repositories.UserMongoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private UserMongoRepository userMongoRepository;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


    @Bean
    public AuthenticationFilter authenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter
                = new AuthenticationFilter(userMongoRepository);
        authenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/login"));
        authenticationFilter.setAuthenticationManager(authenticationManagerBean());
        authenticationFilter.setAuthenticationSuccessHandler(this::loginSuccessHandler);
        authenticationFilter.setAuthenticationFailureHandler(this :: loginFailureHandler);
        return authenticationFilter;
    }

@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // TODO Auto-generated method stub
    auth.userDetailsService(userDetailsService);
}

    @Override
    public void configure(WebSecurity web) throws Exception {
        // TODO Auto-generated method stub
        //auth.userDetailsService(userDetailsService);
        web.ignoring().antMatchers("/login**","/error","/login");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // TODO Auto-generated method stub
        http
                .cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .authorizeRequests()
                .antMatchers("/user**").hasAuthority("user")
                .antMatchers("/vendor**").hasAuthority("vendor")
                .antMatchers("/error").permitAll()
                .anyRequest().authenticated()
                .and().httpBasic()
                .and()
                .logout()
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and().csrf().disable();
                http.addFilter(new AuthenticationFilter(this.userMongoRepository));
    }
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    private void loginSuccessHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        response.setStatus(HttpStatus.OK.value());
    }

    private void loginFailureHandler(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException e) throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }

}
