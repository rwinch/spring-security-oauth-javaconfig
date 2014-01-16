package org.springframework.security.oauth.examples.config;

import java.util.Arrays;
import java.util.Map;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.web.access.ExceptionTranslationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${accessTokenUri}")
	private String accessTokenUri;

	@Value("${userAuthorizationUri}")
	private String userAuthorizationUri;

	@Resource
	private AccessTokenRequest accessTokenRequest;

	@Bean
	public OAuth2ClientContextFilter oauth2ClientFilter() {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		return filter;
	}

	@Bean
	public OAuth2ProtectedResourceDetails sparklr() {
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
		details.setId("sparklr/tonr");
		details.setClientId("tonr");
		details.setClientSecret("secret");
		details.setAccessTokenUri(accessTokenUri);
		details.setUserAuthorizationUri(userAuthorizationUri);
		details.setScope(Arrays.asList("read", "write"));
		return details;
	}

	@Bean
	public OAuth2ProtectedResourceDetails facebook() {
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
		details.setId("facebook");
		details.setClientId("233668646673605");
		details.setClientSecret("33b17e044ee6a4fa383f46ec6e28ea1d");
		details.setAccessTokenUri("https://graph.facebook.com/oauth/access_token");
		details.setUserAuthorizationUri("https://www.facebook.com/dialog/oauth");
		details.setTokenName("oauth_token");
		details.setClientAuthenticationScheme(AuthenticationScheme.form);
		return details;
	}

	@Bean
	public OAuth2ProtectedResourceDetails trusted() {
		ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
		details.setId("sparklr/trusted");
		details.setClientId("my-client-with-registered-redirect");
		details.setAccessTokenUri(accessTokenUri);
		details.setScope(Arrays.asList("trust"));
		return details;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("marissa").password("wombat").roles("USER").and().withUser("sam")
				.password("kangaroo").roles("USER");
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
    	    http.authorizeRequests()
                .antMatchers("/sparklr/**","/facebook/**").hasRole("USER")
                .anyRequest().permitAll()
                .and()
            .addFilterAfter(oauth2ClientFilter(), ExceptionTranslationFilter.class)
            .logout()
                .logoutSuccessUrl("/login.jsp")
                .logoutUrl("/logout.do")
                .permitAll()
                .and()
            .formLogin()
                .loginPage("/login.jsp")
                .loginProcessingUrl("/login.do")
                .failureUrl("/login.jsp?authentication_error=true")
                .usernameParameter("j_username")
                .passwordParameter("j_password")
                .permitAll();
    	// @formatter:on
	}

	@Bean
	public OAuth2RestTemplate facebookRestTemplate() {
		OAuth2RestTemplate template = new OAuth2RestTemplate(facebook(), oauth2ClientContext());
		MappingJacksonHttpMessageConverter converter = new MappingJacksonHttpMessageConverter();
		converter
				.setSupportedMediaTypes(Arrays.asList(MediaType.APPLICATION_JSON, MediaType.valueOf("text/javascript")));
		template.setMessageConverters(Arrays.<HttpMessageConverter<?>> asList(converter));
		return template;
	}

	@Bean
	public OAuth2RestTemplate sparklrRestTemplate() {
		return new OAuth2RestTemplate(sparklr(), oauth2ClientContext());
	}

	@Bean
	public OAuth2RestTemplate trustedClientRestTemplate() {
		return new OAuth2RestTemplate(trusted());
	}

	@Bean
	@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
	protected OAuth2ClientContext oauth2ClientContext() {
		return new DefaultOAuth2ClientContext(accessTokenRequest);
	}
	
	@Configuration
	protected static class ClientContextConfiguration {

		@Bean
		@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
		protected AccessTokenRequest accessTokenRequest(@Value("#{request.parameterMap}")
		Map<String, String[]> parameters, @Value("#{request.getAttribute('currentUri')}")
		String currentUri) {
			DefaultAccessTokenRequest request = new DefaultAccessTokenRequest(parameters);
			request.setCurrentUri(currentUri);
			return request;
		}

	}

}
