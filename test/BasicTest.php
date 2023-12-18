<?php

namespace ParagonIE\CSPBuilderTest;

use PHPUnit\Framework\TestCase;
use ParagonIE\CSPBuilder\CSPBuilder;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Class BasicTest
 * @package ParagonIE\CSPBuilderTest
 */
class BasicTest extends TestCase
{
    /**
     * @throws \Exception
     */
    public function testBasicFromFile()
    {
        $basic = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');
        $basic->addSource('img-src', 'ytimg.com');
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp.out'),
            $basic->getCompiledHeader()
        );

        $noOld = file_get_contents(__DIR__.'/vectors/basic-csp-no-old.out');
        // We expect different output for ytimg.com when we disable legacy
        // browser support (i.e. Safari):
        $this->assertEquals(
            $noOld,
            $basic
                ->disableOldBrowserSupport()
                ->getCompiledHeader()
        );

        $array = $basic->getHeaderArray();
        $this->assertEquals(
            $array,
            [
                'Content-Security-Policy' => $noOld,
                'X-Content-Security-Policy' => $noOld,
                'X-Webkit-CSP' => $noOld
            ]
        );


        $array2 = $basic->getHeaderArray(false);
        $this->assertEquals(
            $array2,
            [
                'Content-Security-Policy' => $noOld
            ]
        );
    }

    /**
     * @throws \Exception
     */
    public function testBasicFromData()
    {
        $data = file_get_contents(__DIR__.'/vectors/basic-csp.json');

        $basic = CSPBuilder::fromData($data);
        $basic->addSource('img-src', 'ytimg.com');

        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp.out'),
            $basic->getCompiledHeader()
        );
    }

    /**
     * @throws \Exception
     */
    public function testNoTrailingSemicolon()
    {
        $csp = (new CSPBuilder())
            ->setSelfAllowed('default-src', true)
            ->addSource('img-src', 'ytimg.com')
            ->disableOldBrowserSupport()
        ;

        $this->assertEquals(
            "default-src 'self'; img-src ytimg.com",
            $csp->getCompiledHeader()
        );
    }

    /**
     * @throws \Exception
     */
    public function testHash()
    {
        $basic = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');
        $basic->hash('script-src', 'Yellow Submarine', 'sha384');
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp-hash.out'),
            $basic->getCompiledHeader()
        );
    }

    /**
     * @throws \Exception
     */
    public function testPreHash()
    {
        $basic = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');
        $hashed = \base64_encode(
            \hash('sha384', 'Yellow Submarine', true)
        );
        $basic->preHash('script-src', $hashed, 'sha384');
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp-hash.out'),
            $basic->getCompiledHeader()
        );
    }

    /**
     * @covers \ParagonIE\CSPBuilder\CSPBuilder
     */
    public function testSourceHttpsConversion()
    {
        /** @var CSPBuilder|MockObject $cspHttp */
        if (PHP_VERSION_ID < 70200) {
            $cspHttp = $this->getMockBuilder(CSPBuilder::class)->setMethods(['isHTTPSConnection'])
                ->disableOriginalConstructor()->getMock();
        } else {
            $cspHttp = $this->getMockBuilder(CSPBuilder::class)->onlyMethods(['isHTTPSConnection'])
                ->disableOriginalConstructor()->getMock();
        }
        $cspHttp->method('isHTTPSConnection')->willReturn(false);

        $cspHttp->addSource('form', 'http://example.com');
        $cspHttp->addSource('form', 'another.com');
        $cspHttp->enableHttpsTransformOnHttpsConnections(); // enabled by default
        /** @var string $compiledCspHttp */
        $compiledCspHttp = $cspHttp->compile();
        $this->assertStringContainsString('http://example.com', $compiledCspHttp);
        $this->assertStringContainsString('http://another.com', $compiledCspHttp);

        /** @var CSPBuilder|MockObject $cspHttps */
        if (PHP_VERSION_ID < 70200) {
            $cspHttps = $this->getMockBuilder(CSPBuilder::class)->setMethods(['isHTTPSConnection'])
                ->disableOriginalConstructor()->getMock();
        } else {
            $cspHttps = $this->getMockBuilder(CSPBuilder::class)->onlyMethods(['isHTTPSConnection'])
                ->disableOriginalConstructor()->getMock();
        }
        $cspHttps->method('isHTTPSConnection')->willReturn(true);

        $cspHttps->addSource('form', 'http://example.com');
        $cspHttps->addSource('form', 'another.com');

        /** @var string $compiledCspHttpsWithConvertEnabled */
        $compiledCspHttpsWithConvertEnabled = $cspHttps->compile();
        $this->assertStringContainsString('https://example.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertStringContainsString('https://another.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertStringNotContainsString('http://example.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertStringNotContainsString('http://another.com', $compiledCspHttpsWithConvertEnabled);

        $cspHttps->disableHttpsTransformOnHttpsConnections();
        $compiledCspHttpsWithConvertDisabled = $cspHttps->compile();
        $this->assertStringContainsString('http://example.com', $compiledCspHttpsWithConvertDisabled);
        $this->assertStringContainsString('http://another.com', $compiledCspHttpsWithConvertDisabled);
    }

    /**
     * @covers CSPBuilder::disableHttpsTransformOnHttpsConnections()
     */
    public function testUpgradeInsecureBeatsDisableHttpsConversionFlag()
    {
        $csp = new CSPBuilder();
        $csp->addSource('form', 'http://example.com');
        $csp->disableHttpsTransformOnHttpsConnections();
        $csp->addDirective('upgrade-insecure-requests');
        $compiled = $csp->compile();
        $this->assertStringContainsString('https://example.com', $compiled);
        $this->assertStringNotContainsString('http://example.com', $compiled);
    }

    /**
     * @covers CSPBuilder::setDataAllowed()
     * @throws \Exception
     */
    public function testAllowDataUris()
    {
        $csp = new CSPBuilder();
        $csp->setDataAllowed('img-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("data:", $compiled);
    }

    /**
     * @covers CSPBuilder::setHttpsAllowed()
     * @throws \Exception
     */
    public function testAllowHttps()
    {
        $csp = new CSPBuilder();
        $csp->setHttpsAllowed('script-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("https:", $compiled);
    }

    /**
     * @covers CSPBuilder::setSelfAllowed()
     * @throws \Exception
     */
    public function testRequireSRI()
    {
        $csp = new CSPBuilder();
        $csp->setSelfAllowed('script-src', true)
            ->addSource('script-src', 'self')
            ->requireSRIFor('script');
        $require = \json_encode($csp->getRequireHeaders());
        $this->assertEquals(
            '[["Content-Security-Policy","require-sri-for script"]]',
            $require
        );
    }

    /**
     * @covers CSPBuilder::setSelfAllowed()
     * @throws \Exception
     */
    public function testAllowSelfUris()
    {
        $csp = new CSPBuilder();
        $csp->setSelfAllowed('img-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("'self'", $compiled);
    }

    /**
     * @covers CSPBuilder::setAllowUnsafeEval()
     * @throws \Exception
     */
    public function testAllowUnsafeEval()
    {
        $csp = new CSPBuilder();
        $csp->setAllowUnsafeEval('script-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("'unsafe-eval'", $compiled);
    }

    /**
     * @covers CSPBuilder::setAllowUnsafeHashes()
     * @throws \Exception
     */
    public function testAllowUnsafeHashes()
    {
        $csp = new CSPBuilder();
        $csp->setAllowUnsafeHashes('script-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("'unsafe-hashes'", $compiled);
    }

    /**
     * @covers CSPBuilder::setAllowUnsafeInline()
     * @throws \Exception
     */
    public function testAllowUnsafeInline()
    {
        $csp = new CSPBuilder();
        $csp->setAllowUnsafeInline('script-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("'unsafe-inline'", $compiled);
    }

    /**
     * @covers CSPBuilder::nonce()
     * @throws \Exception
     */
    public function testNonce()
    {
        $csp = new CSPBuilder();

        $this->assertEmpty($csp->nonce('script-src'));
        $this->assertEmpty($csp->nonce('style-src'));

        $csp->setSelfAllowed('script-src', true);
        $csp->setSelfAllowed('style-src', true);

        $this->assertNotEmpty($csp->nonce('script-src'));
        $this->assertNotEmpty($csp->nonce('style-src'));
    }

    /**
     * @covers CSPBuilder::nonce()
     * @throws \Exception
     */
    public function testNonceWithDefaultSrc()
    {
        $csp = new CSPBuilder();
        $csp->setSelfAllowed('default-src', true);

        $this->assertNotEmpty($csp->nonce('script-src'));
        $this->assertNotEmpty($csp->nonce('style-src'));
    }

    /**
     * @covers \ParagonIE\CSPBuilder\CSPBuilder
     */
    public function testSandbox()
    {
        $csp = new CSPBuilder();
        $csp->setDirective('sandbox');
        $compiled = $csp->compile();

        $this->assertEquals($compiled, 'sandbox');

        $csp->addSource('sandbox', 'allow-scripts');
        $compiled = $csp->compile();

        $this->assertEquals($compiled, 'sandbox allow-scripts');

        $csp->setDirective('sandbox', [
            'allow' => ['allow-popups-to-escape-sandbox'],
        ]);
        $compiled = $csp->compile();

        $this->assertEquals($compiled, 'sandbox allow-popups-to-escape-sandbox');
    }

    /**
     * @covers \ParagonIE\CSPBuilder\CSPBuilder
     */
    public function testRemovingDirectives()
    {
        $csp = new CSPBuilder();
        $csp->addSource('frame-ancestors', 'https://example.com');
        $csp->addSource('style-src', 'https://example.com');
        $compiled = $csp->compile();

        $this->assertStringContainsString('frame-ancestors https://example.com', $compiled);
        $this->assertStringContainsString('style-src https://example.com', $compiled);

        $csp->removeDirective('style-src');
        $compiled = $csp->compile();

        $this->assertStringContainsString('frame-ancestors https://example.com', $compiled);
        $this->assertStringNotContainsString('style-src https://example.com', $compiled);
    }

    public function testSaveSnippetWithHookBeforeSave()
    {
        $data = \file_get_contents(__DIR__ . '/vectors/basic-csp.json');

        $basic = CSPBuilder::fromData($data);
        $basic->addSource('img-src', 'ytimg.com');

        $tempfile = tempnam(sys_get_temp_dir(), '');

        $basic->saveSnippet(
            $tempfile,
            CSPBuilder::FORMAT_NGINX,
            function  ($output) {
                return \str_replace('ytimg', 'foo', $output);
            }  
        );

        $this->assertStringContainsString(
            "img-src 'self' https://foo.com",
            \file_get_contents($tempfile)
        );
    }

    public function testSaveSnippetWithoutHookBeforeSave()
    {
        $data = \file_get_contents(__DIR__ . '/vectors/basic-csp.json');

        $basic = CSPBuilder::fromData($data);
        $basic->addSource('img-src', 'ytimg.com');

        $tempfile = tempnam(sys_get_temp_dir(), '');

        $basic->saveSnippet(
            $tempfile,
            CSPBuilder::FORMAT_NGINX
        );

        $this->assertStringContainsString(
            "img-src 'self' https://ytimg.com",
            \file_get_contents($tempfile)
        );
    }

    /**
     * @covers CSPBuilder::setAllowUnsafeEval()
     * @throws \Exception
     */
    public function testAllowUnsafeHashedAttributes()
    {
        $csp = new CSPBuilder();
        $csp->setAllowUnsafeHashedAttributes('script-src', true);
        $compiled = $csp->compile();

        $this->assertStringContainsString("'unsafe-hashed-attributes'", $compiled);
     }
     
    /**
     * @covers CSPBuilder::allowPluginType()
     * @throws \Exception
     */
    public function testAllowPluginType()
    {
        $csp = new CSPBuilder();
        $csp->allowPluginType('application/x-java-applet');
        $csp->allowPluginType('something/$&§invalid');
        $compiled = $csp->compile();

        $this->assertStringContainsString('plugin-types application/x-java-applet', $compiled);
        $this->assertStringNotContainsString('something', $compiled);
    }
}
