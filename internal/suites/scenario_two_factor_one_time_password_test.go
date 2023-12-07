package suites

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type TwoFactorOneTimePasswordSuite struct {
	*RodSuite
}

func NewTwoFactorOneTimePasswordScenario() *TwoFactorOneTimePasswordSuite {
	return &TwoFactorOneTimePasswordSuite{
		RodSuite: NewRodSuite(""),
	}
}

func (s *TwoFactorOneTimePasswordSuite) SetupSuite() {
	browser, err := NewRodSession(RodSessionWithCredentials(s))
	if err != nil {
		log.Fatal(err)
	}

	s.RodSession = browser

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer func() {
		cancel()
		s.collectScreenshot(ctx.Err(), s.Page)

		s.collectCoverage(s.Page)
		s.MustClose()
	}()

	s.Page = s.doCreateTab(s.T(), HomeBaseURL)
	s.doLoginAndRegisterTOTP(s.T(), s.Context(ctx), "john", "password", false)
}

func (s *TwoFactorOneTimePasswordSuite) TearDownSuite() {
	err := s.RodSession.Stop()

	if err != nil {
		log.Fatal(err)
	}
}

func (s *TwoFactorOneTimePasswordSuite) SetupTest() {
	s.Page = s.doCreateTab(s.T(), HomeBaseURL)
	s.verifyIsHome(s.T(), s.Page)
}

func (s *TwoFactorOneTimePasswordSuite) TearDownTest() {
	s.collectCoverage(s.Page)
	s.MustClose()
}

func (s *TwoFactorOneTimePasswordSuite) TestShouldNotAuthorizeSecretBeforeTwoFactor() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer func() {
		cancel()
		s.collectScreenshot(ctx.Err(), s.Page)
	}()

	targetURL := fmt.Sprintf("%s/secret.html", AdminBaseURL)

	s.doVisit(s.T(), s.Context(ctx), targetURL)

	s.verifyIsFirstFactorPage(s.T(), s.Context(ctx))

	raw := GetLoginBaseURLWithFallbackPrefix(BaseDomain, "/")

	expected, err := url.ParseRequestURI(raw)
	s.Assert().NoError(err)
	s.Require().NotNil(expected)

	query := expected.Query()

	query.Set("rd", targetURL)

	expected.RawQuery = query.Encode()

	rx := regexp.MustCompile(fmt.Sprintf(`^%s(&rm=GET)?$`, regexp.QuoteMeta(expected.String())))

	s.verifyURLIsRegexp(s.T(), s.Context(ctx), rx)
}

func (s *TwoFactorOneTimePasswordSuite) TestShouldAuthorizeSecretAfterTwoFactor() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer func() {
		cancel()
		s.collectScreenshot(ctx.Err(), s.Page)
	}()

	username := testUsername
	password := testPassword

	// Login and register TOTP, logout and login again with 1FA & 2FA.
	targetURL := fmt.Sprintf("%s/secret.html", AdminBaseURL)
	s.doLoginSecondFactorTOTP(s.T(), s.Context(ctx), username, password, false, targetURL)

	// And check if the user is redirected to the secret.
	s.verifySecretAuthorized(s.T(), s.Context(ctx))

	// Leave the secret.
	s.doVisit(s.T(), s.Context(ctx), HomeBaseURL)
	s.verifyIsHome(s.T(), s.Context(ctx))

	// And try to reload it again to check the session is kept.
	s.doVisit(s.T(), s.Context(ctx), targetURL)
	s.verifySecretAuthorized(s.T(), s.Context(ctx))
}

func (s *TwoFactorOneTimePasswordSuite) TestShouldFailTwoFactor() {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer func() {
		cancel()
		s.collectScreenshot(ctx.Err(), s.Page)
	}()

	wrongPasscode := "123456"

	s.doLoginOneFactor(s.T(), s.Context(ctx), testUsername, testPassword, false, BaseDomain, "")
	s.verifyIsSecondFactorPage(s.T(), s.Context(ctx))
	s.doEnterOTP(s.T(), s.Context(ctx), wrongPasscode)
	s.verifyNotificationDisplayed(s.T(), s.Context(ctx), "The One-Time Password might be wrong")
}

func TestRunTwoFactorOneTimePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping suite test in short mode")
	}

	suite.Run(t, NewTwoFactorOneTimePasswordScenario())
}
