import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Easy to Use',
    Svg: require('@site/static/img/terminal.svg').default,
    description: (
      <>
        <code>ipsw</code> was designed from the ground up to be easily installed and
        used to get you up and running quickly with an intuitive CLI.
      </>
    ),
  },
  {
    title: 'Unparalleled Flexibility and Power',
    Svg: require('@site/static/img/apple.svg').default,
    description: (
      <>
        Simply the best tool to use when digging into Apple internals.
      </>
    ),
  },
  {
    title: 'Powered by Go',
    Svg: require('@site/static/img/golang.svg').default,
    description: (
      <>
        Built in a fast and memory safe modern language with a huge community and mature standard lib.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
