package org.example.service;



import lombok.AllArgsConstructor;
import lombok.Data;
import org.example.entities.UserInfo;
import org.example.model.UserInfoDto;
import org.example.repository.RefreshTokenRepository;
import org.example.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


import java.util.HashSet;
import java.util.UUID;
import java.util.regex.Pattern;

@Component
@AllArgsConstructor
@Data
public class UserDetailServiceimp implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@(.+)$";

    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{8,}$";

    @Override
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserInfo user=userRepository.findByUserName(username);
        if(user==null){
            throw new UsernameNotFoundException("could not find user");
        }
        return new CustomUserDetails(user);
    }
    public UserInfo checkIfUserAlreadyExists(UserInfoDto userInfoDto){
        return userRepository.findByUserName(userInfoDto.getUserName());

    }

    public Boolean signupUser(UserInfoDto userInfoDto){
        if(!isValidEmail(userInfoDto.getUserName())){
            throw new IllegalArgumentException("Username is not correct");
        }
        if(!isValidPassword(userInfoDto.getPassword())){
            throw new IllegalArgumentException("Password is not correct");
        }
        userInfoDto.setPassword(passwordEncoder.encode(userInfoDto.getPassword()));
        if(userRepository.findByUserName(userInfoDto.getUserName())!=null){
            return false;
        }
        String userId= UUID.randomUUID().toString();
        userRepository.save(new UserInfo(userId,userInfoDto.getUserName(),userInfoDto.getPassword(),new HashSet<>()));
        return true;
    }
    private Boolean isValidEmail(String email){
        if(email==null || email.isEmpty()){return false;}
        return Pattern.compile(EMAIL_REGEX).matcher(email).matches();
    }
    private Boolean isValidPassword(String password){
        if(password==null || password.isEmpty()){return false;}
        return Pattern.compile(PASSWORD_REGEX).matcher(password).matches();
    }
}
