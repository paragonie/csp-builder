<?php
use ParagonIE\CSPBuilder\CSPBuilder;
use Psr\Http\Message\MessageInterface;

/**
 * 
 */
class BasicTest extends PHPUnit_Framework_TestCase
{
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
    
    public function testHash()
    {
        $basic = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');
        $basic->hash('script-src', 'Yellow Submarine', 'sha384');
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp-hash.out'),
            $basic->getCompiledHeader()
        );
    }
    
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
        /** @var CSPBuilder|\PHPUnit_Framework_MockObject_MockObject $cspHttp */
        $cspHttp = $this->getMockBuilder(CSPBuilder::class)->setMethods(['isHTTPSConnection'])->disableOriginalConstructor()->getMock();
        $cspHttp->method('isHTTPSConnection')->willReturn(false);

        $cspHttp->addSource('form', 'http://example.com');
        $cspHttp->addSource('form', 'another.com');
        $cspHttp->enableHttpsTransformOnHttpsConnections(); // enabled by default
        $compiledCspHttp = $cspHttp->compile();
        $this->assertContains('http://example.com', $compiledCspHttp);
        $this->assertContains('http://another.com', $compiledCspHttp);

        /** @var CSPBuilder|\PHPUnit_Framework_MockObject_MockObject $cspHttps */
        $cspHttps = $this->getMockBuilder(CSPBuilder::class)->setMethods(['isHTTPSConnection'])->disableOriginalConstructor()->getMock();
        $cspHttps->method('isHTTPSConnection')->willReturn(true);

        $cspHttps->addSource('form', 'http://example.com');
        $cspHttps->addSource('form', 'another.com');

        $compiledCspHttpsWithConvertEnabled = $cspHttps->compile();
        $this->assertContains('https://example.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertContains('https://another.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertNotContains('http://example.com', $compiledCspHttpsWithConvertEnabled);
        $this->assertNotContains('http://another.com', $compiledCspHttpsWithConvertEnabled);

        $cspHttps->disableHttpsTransformOnHttpsConnections();
        $compiledCspHttpsWithConvertDisabled = $cspHttps->compile();
        $this->assertContains('http://example.com', $compiledCspHttpsWithConvertDisabled);
        $this->assertContains('http://another.com', $compiledCspHttpsWithConvertDisabled);
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
        $this->assertContains('https://example.com', $compiled);
        $this->assertNotContains('http://example.com', $compiled);
    }

    /**
     * @covers CSPBuilder::setDataAllowed()
     */
    public function testAllowDataUris()
    {
        $csp = new CSPBuilder();
        $csp->setDataAllowed('img-src', true);
        $compiled = $csp->compile();

        $this->assertContains("data:", $compiled);
    }

    /**
     * @covers CSPBuilder::setSelfAllowed()
     */
    public function testAllowSelfUris()
    {
        $csp = new CSPBuilder();
        $csp->setSelfAllowed('img-src', true);
        $compiled = $csp->compile();

        $this->assertContains("'self'", $compiled);
    }

    /*
    public function testInjectCSPHeaderWithoutLegacy()
    {
        $modifiedMessage = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $message         = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $basic           = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');

        $header = $basic
            ->disableOldBrowserSupport()
            ->compile();
        $message
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with('Content-Security-Policy', $header)
            ->willReturn($modifiedMessage);

        self::assertSame($modifiedMessage, $basic->injectCSPHeader($message));
    }

    public function testInjectCSPHeaderWithLegacy()
    {
        $originalMessage  = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $modifiedMessage1 = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $modifiedMessage2 = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $modifiedMessage3 = $this->getMock(MessageInterface::class, ['withAddedHeader']);
        $basic            = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');

        $header = $basic
            ->disableOldBrowserSupport()
            ->compile();
        $originalMessage
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with('Content-Security-Policy', $header)
            ->willReturn($modifiedMessage1);
        $modifiedMessage1
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with('X-Content-Security-Policy', $header)
            ->willReturn($modifiedMessage2);
        $modifiedMessage2
            ->expects(self::once())
            ->method('withAddedHeader')
            ->with('X-Webkit-CSP', $header)
            ->willReturn($modifiedMessage3);

        self::assertSame($modifiedMessage3, $basic->injectCSPHeader($originalMessage, true));
    }
    */
}
