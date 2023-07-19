package com.bolsaideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsaideas.springboot.app.auth.handler.LoginSuccessHandler;

@EnableMethodSecurity(securedEnabled = true)
@Configuration
public class SpringSecurityConfig {
	
@Autowired
private LoginSuccessHandler successHandler;
	
	@Bean
	public static BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests((authz) -> {
			try {
				authz.requestMatchers("/", "/css/**", "/js/**", "/images/**", "/listar").permitAll()
						/*.requestMatchers("/uploads/**").hasAnyRole("USER")
						.requestMatchers("/ver/**").hasRole("USER")
						.requestMatchers("/factura/**").hasRole("ADMIN")
						.requestMatchers("/form/**").hasRole("ADMIN")
						.requestMatchers("/eliminar/**").hasRole("ADMIN")*/
						.anyRequest().authenticated().and().formLogin().successHandler(successHandler)
						.loginPage("/login").permitAll().and().logout().permitAll()
						.and().exceptionHandling().accessDeniedPage("/error_403");

			} catch (Exception e) {
				e.printStackTrace();
			}
		});

		return http.build();

	}

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception {

		PasswordEncoder encoder = passwordEncoder();

//		UserBuilder users = User.builder().passwordEncoder(password -> encoder.encode(password));
		// Esto hace lo mismo que lo anterior, simplifica la expresion lambda
		UserBuilder users = User.builder().passwordEncoder(encoder::encode);

		builder.inMemoryAuthentication().withUser(users.username("admin").password("12345").roles("ADMIN", "USER"))
				.withUser(users.username("user").password("12345").roles("USER"));

	}
}
