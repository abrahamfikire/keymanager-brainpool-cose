package io.mosip.kernel.keymanagerservice.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwksResponseDto {
    private List<JwkKeyDto> keys;
} 