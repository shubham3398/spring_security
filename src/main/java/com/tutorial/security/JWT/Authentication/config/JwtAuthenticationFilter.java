package com.tutorial.security.JWT.Authentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//OncePerRequestFilter will invoke this class when request will be made
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;//create this bean since we want our own implementation
    @Override
    protected void doFilterInternal(
           @NonNull HttpServletRequest request,
           @NonNull HttpServletResponse response,
           @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //Get the header in which token is present
        final String authHeader = request.getHeader("Authorization");//pass the name in getHeader method
        //create the jwt
        final String jwt;
        //user email ie username
        final String userEmail;

        //check valid token
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            //then pass this request and response to next filter
            filterChain.doFilter(request, response);
            return;
        }

        //now extract token from authHeader
        jwt = authHeader.substring(7);

        //now check user already present in database
        //extract userEmail form jwt token
        userEmail = jwtService.extractUsername(jwt);
        System.out.println(userEmail);

        //when user is not authenticated
        if(userEmail == null || SecurityContextHolder.getContext().getAuthentication() == null){
            //here we are getting userDetails from database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //now compare token with userDetails
            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authToken  = new UsernamePasswordAuthenticationToken
                        (userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //set this in securityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
