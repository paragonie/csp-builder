<?php
use ParagonIE\CSPBuilder\CSPBuilder;
use Psr\Http\Message\MessageInterface;

/**
 * 
 */
class BasicTest extends PHPUnit_Framework_TestCase
{
    public function testBasic()
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
}
