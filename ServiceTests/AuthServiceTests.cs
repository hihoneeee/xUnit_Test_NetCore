using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Moq;
using TestWebAPI.Repositories.Interfaces;
using AutoMapper;
using TestWebAPI.Services;
using TestWebAPI.Models;
using TestWebAPI.DTOs.Auth;
using TestWebAPI.Services.Interfaces;
using Microsoft.AspNetCore.Http;
using TestWebAPI.Middlewares;
using TestWebAPI.Helpers;
using TestWebAPI.Helpers.IHelpers;
using TestWebAPI.DTOs.JWT;
using Azure.Core;

namespace XUnitTestWebAPI.ServiceTests
{
    public class AuthServiceTests
    {
        private readonly Mock<IAuthRepositories> _authRepoMock;
        private readonly Mock<IRoleRepositories> _roleRepoMock;
        private readonly Mock<IJWTHelper> _jwtHelperMock;
        private readonly Mock<IJwtServices> _jwtServiceMock;
        private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private readonly Mock<IUserRepositories> _userRepoMock;
        private readonly Mock<IHashPasswordHelper> _hashPasswordHelper;
        private readonly IMapper _mapper;
        private readonly AuthServices _authServices;

        public AuthServiceTests()
        {
            _authRepoMock = new Mock<IAuthRepositories>();
            _roleRepoMock = new Mock<IRoleRepositories>();
            _jwtHelperMock = new Mock<IJWTHelper>();
            _jwtServiceMock = new Mock<IJwtServices>();
            _httpContextAccessorMock = new Mock<IHttpContextAccessor>();
            _userRepoMock = new Mock<IUserRepositories>();
            _hashPasswordHelper = new Mock<IHashPasswordHelper>();

            var config = new MapperConfiguration(cfg =>
            {
                cfg.CreateMap<AuthRegisterDTO, User>();
                cfg.CreateMap<User, AuthRegisterDTO>();
            });
            _mapper = config.CreateMapper();

            _authServices = new AuthServices(
                _mapper,
                _authRepoMock.Object,
                _jwtHelperMock.Object,
                _jwtServiceMock.Object,
                _httpContextAccessorMock.Object,
                _userRepoMock.Object,
                _roleRepoMock.Object,
                _hashPasswordHelper.Object
            );
        }
        [Fact]
        public async Task Register_EmailAlreadyExists_ReturnError()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "Jorge_Turcotte@gmail.com", password = "stringst", roleCode = "D22MD2", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync(new User { first_name = authRegisterDTO.first_name, last_name = authRegisterDTO.last_name, email = authRegisterDTO.email, password = authRegisterDTO.password, roleCode = authRegisterDTO.roleCode });

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Email already exists!", result.message);
        }

        [Fact]
        public async Task Register_RoleNotFound_ReturnError()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "test@example.com", password = "stringst", roleCode = "invalidRole", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync((User)null);
            _roleRepoMock.Setup(repo => repo.GetRoleByCodeAsyn(authRegisterDTO.roleCode)).ReturnsAsync((Role)null);

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Role not found!", result.message);
        }

        [Fact]
        public async Task Register_Success_ReturnSuccess()
        {
            // Arrange
            var authRegisterDTO = new AuthRegisterDTO { email = "hohuy12344@gmail.com", password = "stringst", roleCode = "D22MD2", first_name = "Test", last_name = "test" };
            _authRepoMock.Setup(repo => repo.getByEmail(authRegisterDTO.email)).ReturnsAsync((User)null);
            _roleRepoMock.Setup(repo => repo.GetRoleByCodeAsyn(authRegisterDTO.roleCode)).ReturnsAsync(new Role { value = "Admin", code = authRegisterDTO.roleCode });
            _authRepoMock.Setup(repo => repo.Register(It.IsAny<User>())).ReturnsAsync(new User { first_name = authRegisterDTO.first_name, last_name = authRegisterDTO.last_name, email = authRegisterDTO.email, password = authRegisterDTO.password, roleCode = authRegisterDTO.roleCode });

            // Act
            var result = await _authServices.Register(authRegisterDTO);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Register successfully!", result.message);
        }
        [Fact]
        public async Task Login_EmailNotFound_ReturnError()
        {
            // Arrange
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com" };
            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync((User)null);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Email not found!", result.message);

        }

        [Fact]
        public async Task Login_PasswordUnauthorized_ReturnsError()
        {
            // Assert
            var existingEmail = new User { email = "hohuy12344@gmail.com", password = "stringst", first_name = "string", last_name = "string", roleCode = "D22MD2" };
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com", password = "wrong_password" };

            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync(existingEmail);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(authLoginDTO.password, existingEmail.password)).Returns(false);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Password is wrong!", result.message);
        }

        [Fact]
        public async Task Login_Success_ReturnToken()
        {
            // Assert
            var existingEmail = new User { email = "hohuy12344@gmail.com", password = "stringst", first_name = "string", last_name = "string", roleCode = "D22MD2" };
            var authLoginDTO = new AuthLoginDTO { email = "hohuy12344@gmail.com", password = "stringst" };

            _authRepoMock.Setup(repo => repo.getByEmail(authLoginDTO.email)).ReturnsAsync(existingEmail);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(authLoginDTO.password, existingEmail.password)).Returns(true);
            _jwtHelperMock.Setup(jwt => jwt.GenerateJWTToken(existingEmail.id, existingEmail.roleCode, It.IsAny<DateTime>())).ReturnsAsync("fake_jwt_token");
            _jwtHelperMock.Setup(jwt => jwt.GenerateJWTRefreshToken(existingEmail.id, existingEmail.roleCode, It.IsAny<DateTime>())).ReturnsAsync("fake_refresh_token");
            _jwtServiceMock.Setup(service => service.InsertJWTToken(It.IsAny<jwtDTO>())).Returns(Task.CompletedTask);

            var mockHttpContext = new DefaultHttpContext();
            _httpContextAccessorMock.Setup(_ => _.HttpContext).Returns(mockHttpContext);

            // Act
            var result = await _authServices.Login(authLoginDTO);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Login successfully!", result.message);
            Assert.NotNull(result.accessToken);
            Assert.Equal("fake_jwt_token", result.accessToken);

            // Verify cookie was set
            var setCookieHeader = mockHttpContext.Response.Headers["Set-Cookie"].ToString();
            Assert.Contains("refresh_token", setCookieHeader);
            Assert.Contains("fake_refresh_token", setCookieHeader);
        }

        [Fact]
        public async Task RefreshToken_TokenInvalid_ReturnsError()
        {
            // Assert
            var checkToken = new RefreshTokenDTO { token = "valid_refresh_token" };
            _jwtHelperMock.Setup(jwt => jwt.ValidateRefreshTokenAsync(checkToken.token)).ReturnsAsync(false);

            // Act
            var result = await _authServices.refreshTokenAsync(checkToken.token);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Invalid refresh token!", result.message);
        }

        [Fact]
        public async Task RefreshToken_Success_ReturnToken()
        {
            // Assert
            var checkToken = new RefreshTokenDTO { token = "valid_refresh_token" };
            var userId = 11;
            var userRole = "D22MD2";
            var accessToken = "new_access_token";
            _jwtHelperMock.Setup(jwt => jwt.ValidateRefreshTokenAsync(checkToken.token)).ReturnsAsync(true);
            _jwtHelperMock.Setup(jwt => jwt.GetUserIdFromToken(checkToken.token)).Returns(userId);
            _jwtHelperMock.Setup(jwt => jwt.GetUserRoleFromToken(checkToken.token)).Returns(userRole);
            _jwtHelperMock.Setup(jwt => jwt.GenerateJWTToken(userId, userRole, It.IsAny<DateTime>())).ReturnsAsync(accessToken);

            // Act
            var result = await _authServices.refreshTokenAsync(checkToken.token);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Access token refreshed successfully!", result.message);
            Assert.NotNull(result.accessToken);
            Assert.Equal("new_access_token", result.accessToken);
        }

        [Fact]
        public async Task ChangePassword_UserNotFound_ReturnsError()
        {
            // Assert
            var checkUser = new AuthChangePasswordDTO { id = 100 };
            _userRepoMock.Setup(repo => repo.GetCurrentAsync(checkUser.id)).ReturnsAsync((User)null);

            // Act
            var result = await _authServices.ChangePasswordasync(checkUser);

            // Assert
            Assert.False(result.success);
            Assert.Equal("User not found!", result.message);

        }

        [Fact]
        public async Task ChangePassword_OldPasswordUnauthorized_ReturnsError()
        {
            // Assert
            var user = new User { id = 11, email = "hohuy12344@gmail.com", first_name="string", last_name = "string", password="stringst", roleCode = "D22MD2" };
            var changePassword = new AuthChangePasswordDTO { id = 11, oldPassword = "stringst" };

            _userRepoMock.Setup(repo => repo.GetCurrentAsync(changePassword.id)).ReturnsAsync(user);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(changePassword.oldPassword, user.password)).Returns(false);
            // Act
            var result = await _authServices.ChangePasswordasync(changePassword);

            // Assert
            Assert.False(result.success);
            Assert.Equal("Password is wrong!", result.message);
        }

        [Fact]
        public async Task ChangePassword_NewPasswordUnauthorized_ReturnsError()
        {
            // Assert
            var user = new User { id = 11, email = "hohuy12344@gmail.com", first_name = "string", last_name = "string", password = "stringst", roleCode = "D22MD2" };
            var changePassword = new AuthChangePasswordDTO { id = 11, oldPassword = "stringst", newPassword = "123456789", enterPassword = "12345678" };

            _userRepoMock.Setup(repo => repo.GetCurrentAsync(changePassword.id)).ReturnsAsync(user);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(changePassword.oldPassword, user.password)).Returns(true);
            
            // Act
            var result = await _authServices.ChangePasswordasync(changePassword);

            // Assert
            Assert.False(result.success);
            Assert.Equal("New password and confirmation password do not match!", result.message);
        }

        [Fact]
        public async Task ChangePassword_Success_ReturnSuccess()
        {
            // Assert
            var user = new User { id = 11, email = "hohuy12344@gmail.com", first_name = "string", last_name = "string", password = "stringst", roleCode = "D22MD2" };
            var changePassword = new AuthChangePasswordDTO { id = 11, oldPassword = "stringst", newPassword = "123456789", enterPassword = "123456789" };

            _userRepoMock.Setup(repo => repo.GetCurrentAsync(changePassword.id)).ReturnsAsync(user);
            _hashPasswordHelper.Setup(helper => helper.VerifyPassword(changePassword.oldPassword, user.password)).Returns(true);
            _hashPasswordHelper.Setup(helper => helper.HashPassword(changePassword.newPassword));
            // Act
            var result = await _authServices.ChangePasswordasync(changePassword);

            // Assert
            Assert.True(result.success);
            Assert.Equal("Password change succssefully!", result.message);
        }
    }
}
