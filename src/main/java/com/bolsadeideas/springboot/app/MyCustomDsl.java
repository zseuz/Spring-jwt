package com.bolsadeideas.springboot.app;

//import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.stereotype.Component;

//import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;

@Component
public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity >  {
 
//	@Override
//	public void configure(HttpSecurity httpSecurity)throws Exception {
//		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
//		httpSecurity.addFilter(new JWTAuthenticationFilter(authenticationManager) );
//	}
}
