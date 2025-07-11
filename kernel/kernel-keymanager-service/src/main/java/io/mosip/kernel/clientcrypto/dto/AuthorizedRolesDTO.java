package io.mosip.kernel.clientcrypto.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("clientCryptoAuthRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO {

    private List<String> postcssign;

    private List<String> postcsverifysign;

    private List<String> posttpmencrypt;

    private List<String> posttpmdecrypt;

    private List<String> posttpmsigningpublickey;

    private List<String> posttpmencryptionpublickey;

}