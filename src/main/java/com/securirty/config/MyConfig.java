package com.securirty.config;

import com.securirty.jwt.AuthEntryPoint;
import com.securirty.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class MyConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPoint unauthorized;


    @Bean(name = "customAuthTokenFilter")
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    // this method is copied from SpringBootWebSecurityConfiguration
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.antMatchers("/h2-console/**", "/token/**")
                        .permitAll()
                        .anyRequest().authenticated());

        // hya line mule user login password data cache mdhe save honar nhi
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorized));
        http.httpBasic(withDefaults());
        http.csrf(csrf -> csrf.disable());
        http.headers((headers -> headers.frameOptions(frame -> frame.sameOrigin())));
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        // http.csrf(csrf-> csrf.ignoringAntMatchers("/h2-console/**"));
        return http.build();
    }

    @Bean
    public UserDetailsService detailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }


    @Bean
    public CommandLineRunner userDetailsService() {
        return args -> {

            UserDetails user1 = User.withUsername("user")
                    .password(passwordEncoder().encode("gangurde"))
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("gangurde"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user1);
            jdbcUserDetailsManager.createUser(admin);

        };
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


}
