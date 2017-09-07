/*
 * Copyright (c) 2015 Espark And ©Adarsh Development Services @copyright All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Espark nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.espark.adarsh.configuration.security;

import java.util.Arrays;

import org.omg.CORBA.Environment;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;



@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(final WebSecurity webSecurity) throws Exception {
        webSecurity.ignoring()
        .antMatchers("/css/**")
        .antMatchers("/js/**")
        .antMatchers("/font/**");
    }

    @Override
    protected void configure(final HttpSecurity httpSecurity) throws Exception {

        httpSecurity
        .authorizeRequests()
        .antMatchers("/", "/test").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/LoginPage").defaultSuccessUrl("/UserPage")
        .permitAll()
        .and()
        .csrf().disable()
        .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
        .logoutSuccessUrl("/home")
        .permitAll();

    }

    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }



    @Override
    protected void configure(final AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    	LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl("ldaps://192.168.100.123:3269/");
        contextSource.setBase("DC=c9,DC=local");
        contextSource.setUserDn("CN=Admin,CN=Users,DC=c9,DC=local");
        contextSource.setPassword("Cloud9ers");
        contextSource.afterPropertiesSet();
        
        LdapAuthenticationProviderConfigurer<AuthenticationManagerBuilder> ldapAuthenticationProviderConfigurer = authenticationManagerBuilder.ldapAuthentication();
        ldapAuthenticationProviderConfigurer.contextSource(contextSource)
        .userSearchFilter("sAMAccountName={0}");
    
    	// WAY 2 
    	/*
    	authenticationManagerBuilder.ldapAuthentication()
        .contextSource().url("ldaps://192.168.100.123:3269/dc=c9,dc=local")
        .managerDn("CN=Admin,cn=Users,dc=c9,dc=local").managerPassword("Cloud9ers")
        .and()
        .userSearchFilter("sAMAccountName={0}");
    	// login with all users except Domain Admin because Domain Admin doesn't have userPrincipal name
        //.userSearchBase("CN=Users").userSearchFilter("(userPrincipalName={0}@c9.local)");
         */
    }
}
