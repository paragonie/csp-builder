<?php
declare(strict_types=1);
namespace ParagonIE\CSPBuilder;

use \ParagonIE\ConstantTime\Base64;
use \Psr\Http\Message\MessageInterface;

/**
 * Class CSPBuilder
 * @package ParagonIE\CSPBuilder
 */
class CSPBuilder
{
    const FORMAT_APACHE = 'apache';
    const FORMAT_NGINX = 'nginx';

    /**
     * @var array
     */
    private $policies = [];

    /**
     * @var bool
     */
    private $needsCompile = true;

    /**
     * @var string
     */
    private $compiled = '';

    /**
     * @var bool
     */
    private $reportOnly = false;

    /**
     * @var bool
     */
    protected $supportOldBrowsers = true;

    /**
     * @var bool
     */
    protected $httpsTransformOnHttpsConnections = true;

    /**
     * @var string[]
     */
    private static $directives = [
        'base-uri',
        'default-src',
        'child-src',
        'connect-src',
        'font-src',
        'form-action',
        'frame-ancestors',
        'frame-src',
        'img-src',
        'media-src',
        'object-src',
        'plugin-types',
        'manifest-src',
        'script-src',
        'style-src'
    ];

    /**
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }

    /**
     * Compile the current policies into a CSP header
     *
     * @return string
     */
    public function compile(): string
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array('report-only', $ruleKeys)) {
            $this->reportOnly = !!$this->policies['report-only'];
        } else {
            $this->reportOnly = false;
        }

        $compiled = [];

        foreach(self::$directives as $dir) {
            if (\in_array($dir, $ruleKeys)) {
                if (empty($ruleKeys)) {
                    if ($dir === 'base-uri') {
                        continue;
                    }
                }
                $compiled []= $this->compileSubgroup(
                    $dir,
                    $this->policies[$dir]
                );
            }
        }

        if (!empty($this->policies['report-uri'])) {
            $compiled []= 'report-uri ' . $this->policies['report-uri'] . '; ';
        }
        if (!empty($this->policies['upgrade-insecure-requests'])) {
            $compiled []= 'upgrade-insecure-requests';
        }

        $this->compiled = \implode('', $compiled);
        $this->needsCompile = false;
        return $this->compiled;
    }

    /**
     * Add a source to our allow white-list
     *
     * @param string $directive
     * @param string $path
     *
     * @return self
     */
    public function addSource(string $directive, string $path): self
    {
        switch ($directive) {
            case 'child':
            case 'frame':
            case 'frame-src':
                if ($this->supportOldBrowsers) {
                    $this->policies['child-src']['allow'][] = $path;
                    $this->policies['frame-src']['allow'][] = $path;
                    return $this;
                }
                $directive = 'child-src';
                break;
            case 'connect':
            case 'socket':
            case 'websocket':
                $directive = 'connect-src';
                break;
            case 'font':
            case 'fonts':
                $directive = 'font-src';
                break;
            case 'form':
            case 'forms':
                $directive = 'form-action';
                break;
            case 'ancestor':
            case 'parent':
                $directive = 'frame-ancestors';
                break;
            case 'img':
            case 'image':
            case 'image-src':
                $directive = 'img-src';
                break;
            case 'media':
                $directive = 'media-src';
                break;
            case 'object':
                $directive = 'object-src';
                break;
            case 'js':
            case 'javascript':
            case 'script':
            case 'scripts':
                $directive = 'script-src';
                break;
            case 'style':
            case 'css':
            case 'css-src':
                $directive = 'style-src';
                break;
        }
        $this->policies[$directive]['allow'][] = $path;
        return $this;
    }

    /**
     * Add a directive if it doesn't already exist
     *
     * If it already exists, do nothing
     *
     * @param string $key
     * @param mixed $value
     *
     * @return self
     */
    public function addDirective(string $key, $value = null): self
    {
        if ($value === null) {
            if (!isset($this->policies[$key])) {
                $this->policies[$key] = true;
            }
        } elseif (empty($this->policies[$key])) {
            $this->policies[$key] = $value;
        }
        return $this;
    }

    /**
     * Add a plugin type to be added
     *
     * @param string $mime
     * @return self
     */
    public function allowPluginType(string $mime = 'text/plain'): self
    {
        $this->policies['plugin-types']['types'] []= $mime;

        $this->needsCompile = true;
        return $this;
    }

    /**
     * Disable old browser support (e.g. Safari)
     *
     * @return self
     */
    public function disableOldBrowserSupport(): self
    {
        $this->needsCompile = $this->supportOldBrowsers !== false;
        $this->supportOldBrowsers = false;
        return $this;
    }

    /**
     * Enable old browser support (e.g. Safari)
     *
     * This is enabled by default
     *
     * @return self
     */
    public function enableOldBrowserSupport(): self
    {
        $this->needsCompile = $this->supportOldBrowsers !== true;
        $this->supportOldBrowsers = true;
        return $this;
    }

    /**
     * Factory method - create a new CSPBuilder object from a JSON file
     *
     * @param string $filename
     * @return self
     * @throws \Exception
     */
    public static function fromFile(string $filename = ''): self
    {
        if (!\file_exists($filename)) {
            throw new \Exception($filename.' does not exist');
        }
        $contents = \file_get_contents($filename);
        if (!\is_string($contents)) {
            throw new \Exception('Could not read file contents');
        }
        return self::fromData($contents);
    }

    /**
     * Factory method - create a new CSPBuilder object from a JSON data
     *
     * @param string $data
     * @return self
     * @throws \Exception
     */
    public static function fromData($data = ''): self
    {
        $array = \json_decode($data, true);

        if(!\is_array($array)) {
            throw new \Exception('Is not array valid');
        }

        return new CSPBuilder($array);
    }

    /**
     * Get the formatted CSP header
     *
     * @return string
     */
    public function getCompiledHeader(): string
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        return $this->compiled;
    }

    /**
     * Get an associative array of headers to return.
     *
     * @param bool $legacy
     * @return array<string, string>
     */
    public function getHeaderArray(bool $legacy = true): array
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        $return = [];
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $return[(string) $key] = $this->compiled;
        }
        return $return;
    }

    /**
     * Add a new hash to the existing CSP
     *
     * @param string $directive
     * @param string $script
     * @param string $algorithm
     * @return self
     */
    public function hash(
        string $directive = 'script-src',
        string $script = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => Base64::encode(
                    \hash($algorithm, $script, true)
                )
            ];
        }
        return $this;
    }

    /**
     * Add a new (pre-calculated) base64-encoded hash to the existing CSP
     *
     * @param string $directive
     * @param string $hash
     * @param string $algorithm
     * @return self
     */
    public function preHash(
        string $directive = 'script-src',
        string $hash = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => $hash
            ];
        }
        return $this;
    }

    /**
     * PSR-7 header injection
     *
     * @param \Psr\Http\Message\MessageInterface $message
     * @param bool $legacy
     * @return \Psr\Http\Message\MessageInterface
     */
    function injectCSPHeader(MessageInterface $message, bool $legacy = false): MessageInterface
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $message = $message->withAddedHeader($key, $this->compiled);
        }
        return $message;
    }

    /**
     * Add a new nonce to the existing CSP
     *
     * @param string $directive
     * @param string $nonce (if empty, it will be generated)
     * @return string
     */
    public function nonce(string $directive = 'script-src', string $nonce = ''): string
    {
        $ruleKeys = \array_keys($this->policies);
        if (!\in_array($directive, $ruleKeys)) {
            return '';
        }

        if (empty($nonce)) {
            $nonce = Base64::encode(\random_bytes(18));
        }
        $this->policies[$directive]['nonces'] []= $nonce;
        return $nonce;
    }

    /**
     * Save CSP to a snippet file
     *
     * @param string $outputFile Output file name
     * @param string $format Which format are we saving in?
     * @return bool
     * @throws \Exception
     */
    public function saveSnippet(
        string $outputFile,
        string $format = self::FORMAT_NGINX
    ): bool {
        if ($this->needsCompile) {
            $this->compile();
        }

        // Are we doing a report-only header?
        $which = $this->reportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        switch ($format) {
            case self::FORMAT_NGINX:
                // In PHP < 7, implode() is faster than concatenation
                $output = \implode('', [
                    'add_header ',
                    $which,
                    ' "',
                    \rtrim($this->compiled, ' '),
                    '";',
                    "\n"
                ]);
                break;
            case self::FORMAT_APACHE:
                $output = \implode('', [
                    'Header add ',
                    $which,
                    ' "',
                    \rtrim($this->compiled, ' '),
                    '"',
                    "\n"
                ]);
                break;
            default:
                throw new \Exception('Unknown format: '.$format);
        }
        return \file_put_contents($outputFile, $output) !== false;
    }

    /**
     * Send the compiled CSP as a header()
     *
     * @param bool $legacy Send legacy headers?
     *
     * @return bool
     * @throws \Exception
     */
    public function sendCSPHeader(bool $legacy = true): bool
    {
        if (\headers_sent()) {
            throw new \Exception('Headers already sent!');
        }
        if ($this->needsCompile) {
            $this->compile();
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            \header($key.': '.$this->compiled);
        }
        return true;
    }

    /**
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws \Exception
     */
    public function setDataAllowed(string $directive = '', bool $allow = false): self
    {
        if (!\in_array($directive, self::$directives)) {
            throw new \Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['data'] = $allow;
        return $this;
    }

    /**
     * Allow self URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws \Exception
     */
    public function setSelfAllowed(string $directive = '', bool $allow = false): self
    {
        if (!\in_array($directive, self::$directives)) {
            throw new \Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['self'] = $allow;
        return $this;
    }

    /**
     * Allow unsafe-eval
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws \Exception
     */
    public function setAllowUnsafeEval(string $directive = '', bool $allow = false): self
    {
        if (!\in_array($directive, self::$directives)) {
            throw new \Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-eval'] = $allow;
        return $this;
    }

    /**
     * Allow unsafe-inline
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws \Exception
     */
    public function setAllowUnsafeInline(string $directive = '', bool $allow = false): self
    {
        if (!\in_array($directive, self::$directives)) {
            throw new \Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-inline'] = $allow;
        return $this;
    }

    /**
     * Set a directive
     *
     * @param string $key
     * @param mixed $value
     *
     * @return self
     */
    public function setDirective(string $key, $value = []): self
    {
        $this->policies[$key] = $value;
        return $this;
    }

    /**
     * Compile a subgroup into a policy string
     *
     * @param string $directive
     * @param mixed $policies
     *
     * @return string
     */
    protected function compileSubgroup(string $directive, $policies = []): string
    {
        if ($policies === '*') {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            if ($directive === 'plugin-types') {
                return '';
            }
            return $directive." 'none'; ";
        }
        $ret = $directive.' ';
        if ($directive === 'plugin-types') {
            // Expects MIME types, not URLs
            return $ret . \implode(' ', $policies['allow']).'; ';
        }
        if (!empty($policies['self'])) {
            $ret .= "'self' ";
        }

        if (!empty($policies['allow'])) {
            foreach ($policies['allow'] as $url) {
                $url = \filter_var($url, FILTER_SANITIZE_URL);
                if ($url !== false) {
                    if ($this->supportOldBrowsers) {
                        if (\strpos($url, '://') === false) {
                            if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections) || !empty($this->policies['upgrade-insecure-requests'])) {
                                // We only want HTTPS connections here.
                                $ret .= 'https://'.$url.' ';
                            } else {
                                $ret .= 'https://'.$url.' http://'.$url.' ';
                            }
                        }
                    }
                    if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections) || !empty($this->policies['upgrade-insecure-requests'])) {
                        $ret .= \str_replace('http://', 'https://', $url).' ';
                    } else {
                        $ret .= $url.' ';
                    }
                }
            }
        }

        if (!empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $hashval) {
                    $ret .= \implode('', [
                        "'",
                        \preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        \preg_replace('/[^A-Za-z0-9\+\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }

        if (!empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                $ret .= \implode('', [
                    "'nonce-",
                    \preg_replace('/[^A-Za-z0-9\+\/=]/', '', $nonce),
                    "' "
                ]);
            }
        }

        if (!empty($policies['types'])) {
            foreach ($policies['types'] as $type) {
                $ret .= $type.' ';
            }
        }

        if (!empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }
        if (!empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval' ";
        }
        if (!empty($policies['data'])) {
            $ret .= "data: ";
        }
        return \rtrim($ret, ' ').'; ';
    }

    /**
     * Get an array of header keys to return
     *
     * @param bool $legacy
     * @return array
     */
    protected function getHeaderKeys(bool $legacy = true): array
    {
        // We always want this
        $return = [
            $this->reportOnly
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy'
        ];

        // If we're supporting legacy devices, include these too:
        if ($legacy) {
            $return []= $this->reportOnly
                ? 'X-Content-Security-Policy-Report-Only'
                : 'X-Content-Security-Policy';
            $return []= $this->reportOnly
                ? 'X-Webkit-CSP-Report-Only'
                : 'X-Webkit-CSP';
        }
        return $return;
    }

    /**
     * Is this user currently connected over HTTPS?
     *
     * @return bool
     */
    protected function isHTTPSConnection(): bool
    {
        if (!empty($_SERVER['HTTPS'])) {
            return $_SERVER['HTTPS'] !== 'off';
        }
        return false;
    }

    /**
     * Disable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * @return self
     */
    public function disableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = $this->httpsTransformOnHttpsConnections !== false;
        $this->httpsTransformOnHttpsConnections = false;

        return $this;
    }

    /**
     * Enable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * This is enabled by default
     *
     * @return self
     */
    public function enableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = $this->httpsTransformOnHttpsConnections !== true;
        $this->httpsTransformOnHttpsConnections = true;

        return $this;
    }
}
