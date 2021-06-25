<?php

namespace Knojector\SteamAuthenticationBundle\Security\Firewall;

use Knojector\SteamAuthenticationBundle\Security\Authentication\Token\SteamUserToken;
use Knojector\SteamAuthenticationBundle\Security\Authentication\Validator\RequestValidatorInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\AbstractListener;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

/**
 * @author Knojector <dev@knojector.xyz>
 */
class SteamListener extends AbstractListener
{
    /**
     * @var AuthenticationManagerInterface
     */
    private $authenticationManager;

    /**
     * @var string
     */
    private $loginRedirect;

    /**
     * @var RouterInterface
     */
    private $router;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /** @var RequestValidatorInterface */
    private $requestValidator;

    /**
     * @param AuthenticationManagerInterface $authenticationManager
     * @param RouterInterface $router
     * @param string $loginRedirect
     * @param TokenStorageInterface $tokenStorage
     */
    public function __construct(
        AuthenticationManagerInterface $authenticationManager,
        RouterInterface $router,
        string $loginRedirect,
        TokenStorageInterface $tokenStorage,
        RequestValidatorInterface $requestValidator
    )
    {
        $this->authenticationManager = $authenticationManager;
        $this->router = $router;
        $this->loginRedirect = $loginRedirect;
        $this->tokenStorage = $tokenStorage;
        $this->requestValidator = $requestValidator;
    }

    /**
     * Tells whether the authenticate() method should be called or not depending on the incoming request.
     *
     * Returning null means authenticate() can be called lazily when accessing the token storage.
     */
    public function supports(Request $request): ?bool
    {
        $this->requestValidator->setRequest($request);

        if (!$this->requestValidator->validate()) {
            return false;
        }

        return true;
    }

    /**
     * Does whatever is required to authenticate the request, typically calling $event->setResponse() internally.
     */
    public function authenticate(RequestEvent $event)
    {
        $request = $event->getRequest();
        $claimedId = str_replace('https://steamcommunity.com/openid/id/', '', $request->query->get('openid_claimed_id'));

        $token = new SteamUserToken();
        $token->setUsername($claimedId);

        $authToken = $this->authenticationManager->authenticate($token);
        $this->tokenStorage->setToken($authToken);


        $event->setResponse(new RedirectResponse(
            $this->router->generate($this->loginRedirect)
        ));
    }
}
