package com.app.core.security;

import java.util.Arrays;

import com.app.core.entity.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

import static com.app.core.entity.model.Permission.ADMIN_READ;
import static com.app.core.entity.model.Permission.MANAGER_READ;
import static com.app.core.entity.model.Role.USER;
import static org.springframework.http.HttpMethod.*;

//import static com.app.core.entity.model.Role.*;

//import static org.springframework.http.HttpMethod.GET;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	private static final String[] WHITE_LIST_URL = { "/api/v1/auth/**", "/v2/api-docs",
			"/v3/api-docs", "/v3/api-docs/**", "/swagger-resources", "/swagger-resources/**", "/configuration/ui",
			"/configuration/security", "/swagger-ui/**", "/webjars/**", "/swagger-ui.html" };

	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	private final AuthenticationProvider authenticationProvider;
	private final LogoutHandler logoutHandler;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		return httpSecurity.csrf(csrf -> {
			csrf.disable();
		}).authorizeHttpRequests(authResquest -> {
			authResquest.requestMatchers(WHITE_LIST_URL).permitAll();
			 authResquest.requestMatchers(GET,"/api/v1/user/**").hasRole("USER");
			 authResquest.requestMatchers(POST,"/api/v1/admin/**").hasRole("ADMIN");
			 authResquest.requestMatchers(PUT,"/api/v1/admin/**").hasRole("ADMIN");
			 authResquest.requestMatchers(DELETE,"/api/v1/admin/**").hasRole("ADMIN");
			authResquest.anyRequest().authenticated();
		}).sessionManagement(
				sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider)
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class).logout(logout -> {
					logout.logoutUrl("/api/v1/auth/logout");
					logout.addLogoutHandler(logoutHandler);
					logout.logoutSuccessHandler(
							(request, response, authentication) -> SecurityContextHolder.clearContext());
				})
				 .cors(Customizer.withDefaults())
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
//		return httpSecurity
//				.csrf(csrf -> {csrf.disable();
//		})
//				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//				.authorizeHttpRequests(auth -> auth
//						.requestMatchers(HttpMethod.POST, "/api/v1/auth/**").permitAll()
//						.requestMatchers(GET,"/api/v1/user/**").authenticated())
//
//
////        Add JWT token filter
//				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
//				.build();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(Arrays.asList("Authorization", "Requestor-Type"));
		configuration.setExposedHeaders(Arrays.asList("X-Get-Header"));
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
