package com.nelioalves.cursomc.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.nelioalves.cursomc.security.JWTAuthenticationFilter;
import com.nelioalves.cursomc.security.JWTUtil;


@Configuration
@EnableWebSecurity
public class SecuirityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private Environment env;
	
	@Autowired
	private JWTUtil jwtUtil;
	
	@Autowired
	private UserDetailsService userDetailsService;

	public static final String[] PUBLIC_MATCHES = { 
			"/h2-console/**"			
	};
	
	public static final String[] PUBLIC_MATCHES_GET = { 			
			"/produtos/**", 
			"/categorias/**",
			"/clientes/**"
	};

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		
		if(Arrays.asList(env.getActiveProfiles()).contains("test")) {
			httpSecurity.headers().frameOptions().disable();
			
		}
		
		httpSecurity.cors().and().csrf().disable();
		httpSecurity.authorizeRequests()
		.antMatchers(HttpMethod.GET, PUBLIC_MATCHES_GET).permitAll()
		.antMatchers(PUBLIC_MATCHES).permitAll()
		.anyRequest().authenticated();
		httpSecurity.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtUtil));
		httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
	}
	
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
	}
	
	@Bean
	  CorsConfigurationSource corsConfigurationSource() {
	    final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	    source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
	    return source;
	  }
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
