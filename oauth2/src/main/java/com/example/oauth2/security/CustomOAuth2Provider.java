package com.example.oauth2.security;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;


public enum CustomOAuth2Provider {
    KAKAO {
        @Override
        public ClientRegistration.Builder getBuilder() {
            return getBuilder("kakao", ClientAuthenticationMethod.POST)
                    .scope("profile", "talk_message") // ��û�� ����
                    .authorizationUri("https://kauth.kakao.com/oauth/authorize") // authorization code ��� API
                    .tokenUri("https://kauth.kakao.com/oauth/token") // access Token ��� API
                    .userInfoUri("https://kapi.kakao.com/v2/user/me") // ���� ���� ��ȸ API
                    .userNameAttributeName("id") // userInfo API Response���� ���� ID ������Ƽ
                    .clientName("Kakao"); // spring ������ �ν��� OAuth2 Provider Name
           
        }
    };

    private static final String DEFAULT_LOGIN_REDIRECT_URL = "{baseUrl}/login/oauth2/code/{registrationId}";
   
	/*
	 * @Resource private Environment env;
	 */
    
    protected final ClientRegistration.Builder getBuilder(String registrationId,
                                                          ClientAuthenticationMethod method) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId)
        		.clientAuthenticationMethod(method)                                          
        		.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) 
        		.redirectUri(CustomOAuth2Provider.DEFAULT_LOGIN_REDIRECT_URL);
        	//	.redirectUriTemplate(CustomOAuth2Provider.DEFAULT_LOGIN_REDIRECT_URL);
        
        return builder;
    }

    public abstract ClientRegistration.Builder getBuilder();
}
