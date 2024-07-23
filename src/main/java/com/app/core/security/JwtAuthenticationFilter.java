package com.app.core.security;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.app.core.security.repository.TokenRepository;
import com.app.core.security.service.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;



@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	final static String BEARER_SPACE = "Bearer ";

	private final JwtService jwtService;
	private final UserDetailsService userDetailsService;
	private final TokenRepository tokenRepository;

	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain)
			throws ServletException, IOException {

		if (request.getServletPath().contains("/api/v1/auth")) {
			filterChain.doFilter(request, response);
			return;
		}

		final String jwt = getTokenFromRequest(request);
		final String username;

		if (jwt == null) {
			filterChain.doFilter(request, response);
			return;
		}

		username = jwtService.extractUsernameFromToken(jwt);

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);

			boolean isTokenValid = tokenRepository.findByToken(jwt)
					.map(t -> !t.isExpired() && !t.isRevoked())
					.orElse(false);

			if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, null,
						userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}

		filterChain.doFilter(request, response);

	}
//@Override
//protected void doFilterInternal(
//		@NonNull HttpServletRequest request,
//		@NonNull HttpServletResponse response,
//		@NonNull FilterChain filterChain)
//		throws ServletException, IOException {
//
//	if (request.getServletPath().contains("/api/v1/auth")) {
//		filterChain.doFilter(request, response);
//		return;
//	}
//
//	final String jwt = getTokenFromRequest(request);
//	final String username;
//
//	if (jwt == null) {
//		filterChain.doFilter(request, response);
//		return;
//	}
//
//	username = jwtService.extractUsernameFromToken(jwt);
//
//	if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//		boolean isTokenValid = tokenRepository.findByToken(jwt)
//				.map(t -> !t.isExpired() && !t.isRevoked())
//				.orElse(false);
//
//		if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
//			// Extract roles from JWT
//			Claims claims = jwtService.extractAllClaims(jwt);
//			String roles = claims.get("roles", String.class);
//
//			System.out.println(roles);
//
//			// Convert roles to GrantedAuthority objects
//			List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(roles);
//
//			System.out.println(authorities);
//			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//					username,
//					null,
//					authorities
//			);
//			authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//			SecurityContextHolder.getContext().setAuthentication(authToken);
//		}
//	}
//
//	filterChain.doFilter(request, response);
//}

//	@Override
//	protected void doFilterInternal(
//			@NonNull HttpServletRequest request,
//			@NonNull HttpServletResponse response,
//			@NonNull FilterChain filterChain)
//			throws ServletException, IOException {
//
//		if (request.getServletPath().contains("/api/v1/auth")) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//
//		final String jwt = getTokenFromRequest(request);
//		final String username;
//
//		if (jwt == null) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//
//		username = jwtService.extractUsernameFromToken(jwt);
//
//		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//
//			boolean isTokenValid = tokenRepository.findByToken(jwt)
//					.map(t -> !t.isExpired() && !t.isRevoked())
//					.orElse(false);
//
//			if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) {
//				Claims claims = jwtService.extractAllClaims(jwt);
//				List<String> roles = claims.get("roles", List.class);
//
//				Collection<? extends GrantedAuthority> authorities = roles != null ?
//						roles.stream()
//								.map(SimpleGrantedAuthority::new)
//								.collect(Collectors.toList())
//						: List.of();
//
//				UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//						userDetails,
//						null,
//						authorities
//				);
//
//				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//				SecurityContextHolder.getContext().setAuthentication(authToken);
//			}
//		}
//
//		filterChain.doFilter(request, response);
//	}







	private String getTokenFromRequest(HttpServletRequest request) {
		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (StringUtils.hasText(authHeader) && authHeader.startsWith(BEARER_SPACE)) {
			return authHeader.replace(BEARER_SPACE, "");
		}

		return null;
	}

}
