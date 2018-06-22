package com.aek56.microservice.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.aek56.microservice.auth.security.JwtAuthenticationEntryPoint;
import com.aek56.microservice.auth.security.JwtAuthenticationTokenFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtAuthenticationEntryPoint unauthorizedHandler;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		authenticationManagerBuilder.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
		return new JwtAuthenticationTokenFilter();
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				// we don't need CSRF because our token is invulnerable
				.csrf().disable()

				.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()

				// don't create session
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()

				.authorizeRequests()
				.antMatchers(
						"/admin", 
						/* "/cache/permission/list", */
						"/authByLoginName",
						"/auth4WechatOfficialAccounts",
						"/authByLoginNameForWexin", 
						"/cache/permission/delbymobile/**",
						"/cache/permission/delbyrole/**", 
						"/cache/module/mod/**", 
						"/cache/user/delbymobile/**",
						"/cache/user/delbytenant/**", 
						"/weixin", 
						"/weixin/callback", 
						"/weixin/getOpenId",
						"/weixin/token", 
						"/weixin/autologin", 
						"/weixin/isbinding", 
						"/weixin/binding",
						"/weixin/validToken",
						"/weixin/uploadWeiXinImage",
						"/auth"
				)
				.permitAll()
				// .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

				// allow anonymous resource requests
				.antMatchers(
						HttpMethod.GET, 
						"/", 
						"/*.html", 
						"/favicon.ico", 
						"/**/*.html", 
						"/**/*.css", 
						"/**/*.js"
				)
				.permitAll().antMatchers("/webjars/**").permitAll().antMatchers("/swagger-resources/**").permitAll()
				.antMatchers("/v2/api-docs").permitAll().antMatchers("/images/*.jpg").permitAll()
				.antMatchers("/images/*.png").permitAll().antMatchers("/**/*.js").permitAll().antMatchers("/**/*.css")
				.permitAll().antMatchers("/**/*.woff").permitAll().antMatchers("/**/*.woff2").permitAll()
				.antMatchers("/**/*.jsp").permitAll().antMatchers("/**/*.html").permitAll().antMatchers("/favicon.ico")
				.permitAll()
				//.antMatchers("/logout-success").permitAll()
				.antMatchers("/sendLoginPwd").permitAll().anyRequest().authenticated();

		// sample logout customization
		httpSecurity.logout().deleteCookies("JSESSIONID")
				// .invalidateHttpSession(false)
				.logoutUrl("/logout");
		// .logoutSuccessUrl("/logout-success");

		// Custom JWT based security filter
		httpSecurity.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

		// disable page caching
		httpSecurity.headers().cacheControl();
	}

}