package be.ecornely.discovery;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("srv-app-discovery").password("$2a$10$Y5fkQx.flB0GXB3uyTdFZeKckvI/p.A8e6.FM5oY66DV7R8Q8CeOG").roles("ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/acutator/**").permitAll().anyRequest().authenticated().and().httpBasic().and().csrf().ignoringAntMatchers("/eureka/**", "/acutator/**");
	}
	
	public static void main(String[] args) {
		String pwd = new BCryptPasswordEncoder().encode("generat3aRand0mStrin5");
		System.out.println("pwd:"+pwd);
	}

	
}
