package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig {

	   @Autowired
	    private BCryptPasswordEncoder passwordEncoder;
		
	    @Autowired
	    private JpaUserDetailsService userDetailsService;
	    
	    @Autowired
	    private AuthenticationConfiguration authenticationConfiguration;
	    
	    @Autowired
	    private JWTService jwtService;
		
	    @Bean
	    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    	
			http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale").permitAll()
			.anyRequest().authenticated()
			.and()
			.addFilter(new JWTAuthenticationFilter(authenticationConfiguration.getAuthenticationManager(),jwtService))
			.addFilter(new JWTAuthorizationFilter(authenticationConfiguration.getAuthenticationManager(),jwtService))
			.csrf().disable()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			
	        return http.build();
	    }    
	 
	    @Autowired
	    public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception
	    {
	        build.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	    }
		
}
