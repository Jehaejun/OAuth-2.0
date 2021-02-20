package com.example.oauth2.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;



@Controller
public class OAuth2Controller {
	 
	// 기본 URL 설정
    private static String authorizationRequestBaseUri = "/oauth2/authorization";
    Map<String, String> oauth2AuthenticationUrls = new HashMap<String, String>();
    
    @Autowired 
    private ClientRegistrationRepository clientRegistrationRepository;
    
	// 로그인 시도 이후 받아온 정보
	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;
	 
	/*
	 * @GetMapping({ "", "/" }) public String getAuthorizationMessage() { return
	 * "home"; }
	 * 
	 * @GetMapping("/login") public String login() { return "login"; }
	 */

	@GetMapping("/login")
	public String login(Model model) {


		
		
		Iterable<ClientRegistration> clientRegistrations = null;
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}

		clientRegistrations.forEach(registration -> oauth2AuthenticationUrls.put(registration.getClientName(),
				authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
		model.addAttribute("urls", oauth2AuthenticationUrls);
		 
		return "login.html";
	}
		
	@GetMapping({ "/loginSuccess", "/hello" })
	public void loginSuccess(HttpServletResponse response, Model model, OAuth2AuthenticationToken authentication) throws Exception {
		System.out.println("111~~~~~~~~~~~~~~~~" + authentication.getName());

		
		 OAuth2AuthorizedClient client = authorizedClientService
		 .loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(),
		 authentication.getName());
		 
		 String userInfoEndpointUri =
		 client.getClientRegistration().getProviderDetails().getUserInfoEndpoint().
		 getUri();
		 
		 if (StringUtils.hasText(userInfoEndpointUri)) {
			 RestTemplate restTemplate = new RestTemplate();
			/*
			 * HttpHeaders headers = new HttpHeaders();
			 * headers.add(HttpHeaders.AUTHORIZATION, "Bearer " +
			 * client.getAccessToken().getTokenValue());
			 * 
			 * 
			 * HttpEntity<Map> entity = new HttpEntity(headers); ResponseEntity response =
			 * restTemplate.exchange(siteUrlCustoom(authentication.
			 * getAuthorizedClientRegistrationId(), userInfoEndpointUri), HttpMethod.GET,
			 * entity, Map.class); Map userAttributes = (Map) response.getBody();
			 * 
			 * model.addAttribute("userInfo", userAttributes);
			 */
			 Cookie myCookie = new Cookie("cookieName", client.getAccessToken().getTokenValue());
			 //  myCookie.setMaxAge(쿠키 expiration 타임 (int));
			   myCookie.setPath("/"); // 모든 경로에서 접근 가능 하도록 설정
			   response.addCookie(myCookie);
		 }
		 
	//	 URI redirectUri = new URI("http://127.0.0.1");
		 
	 //    HttpHeaders httpHeaders = new HttpHeaders();
	  //   httpHeaders.add("test", "123123");
	  //   httpHeaders.setLocation(redirectUri);
	     
	 //    return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		 //response.
	     response.sendRedirect("http://127.0.0.1");
		// "redirect:http://127.0.0.1";
		//return "hello.html";
	}

	@GetMapping("/testLogOut")
	public String loginFailure(HttpServletRequest request) {
		System.out.println("222");
    HttpSession session = request.getSession();
    session.invalidate();
	
	return "hello.html";
	}
	
	  /**
     * 소셜 종류에 따라 URL 구성 변경
     * @param site
     * @return
     */
    protected String siteUrlCustoom(String site, String baseUrl){
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(baseUrl);

        if(site.equals("facebook")){
            uriBuilder.queryParam("fields", "name,email,picture,locale");
        }

        return uriBuilder.toUriString();
    }
}
