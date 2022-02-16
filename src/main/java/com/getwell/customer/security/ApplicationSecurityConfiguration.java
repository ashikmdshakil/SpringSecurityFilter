package com.getwell.customer.security;

import com.getwell.customer.repositories.UserMongoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

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

   /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // TODO Auto-generated method stub
       auth.authenticationProvider(authenticationProvider());
    }*/

/*    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // TODO Auto-generated method stub
        //auth.userDetailsService(userDetailsService);
        web.ignoring().antMatchers("/**");
    }*/

    @Bean
    public AuthenticationFilter authenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter
                = new AuthenticationFilter(userMongoRepository);
        //authenticationFilter.setAuthenticationSuccessHandler(this::loginSuccessHandler);
        //authenticationFilter.setAuthenticationFailureHandler(this::loginFailureHandler);
        authenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/**"));
        //authenticationFilter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatchers("/vendorTest",""));
        authenticationFilter.setAuthenticationManager(authenticationManagerBean());
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
        web.ignoring().antMatchers("/login**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // TODO Auto-generated method stub
        http
                .cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .authorizeRequests()
                //.antMatchers("/login**").permitAll()
                .antMatchers("/user**").hasAuthority("user")
                .antMatchers("/vendor**").hasAuthority("vendor")
                //.antMatchers("/logout").hasAnyAuthority("user","vendor")
                //.antMatchers("/admin**").hasAuthority("admin")
                //.antMatchers("/moderator**").hasAuthority("moderator")
                //.antMatchers("/vendor**").hasAuthority("vendor")
                //.antMatchers("/salesman**").hasAuthority("salesman")
                //.antMatchers("/login").permitAll()
                //.antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and().httpBasic()
                .and()
                .logout()
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .and().csrf().disable();
        http.addFilterBefore(authenticationFilter(), AuthenticationFilter.class);
        //http.addFilterBefore(new AuthenticationFilter(userMongoRepository), AuthenticationFilter.class).addFilter(new AuthorizationFilter(userMongoRepository,authenticationManagerBean()));
    }
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /*@Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }*/

 /*   @Bean
    @Scope(scopeName = "prototype")
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

/*    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurerAdapter() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("GET", "POST")
                        .allowedOrigins("*");
            }
        };
    }*/
}
